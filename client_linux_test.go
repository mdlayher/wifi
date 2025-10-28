//go:build linux
// +build linux

package wifi

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

func TestLinux_clientInterfacesOK(t *testing.T) {
	want := []*Interface{
		{
			Index:        1,
			Name:         "wlan0",
			HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
			PHY:          0,
			Device:       1,
			Type:         InterfaceTypeStation,
			Frequency:    2412,
		},
		{
			HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xae},
			PHY:          0,
			Device:       2,
			Type:         InterfaceTypeP2PDevice,
		},
	}

	const flags = netlink.Request | netlink.Dump

	c := testClient(t, genltest.CheckRequest(familyID, unix.NL80211_CMD_GET_INTERFACE, flags,
		mustMessages(t, unix.NL80211_CMD_NEW_INTERFACE, want),
	))

	got, err := c.Interfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected interfaces (-want +got):\n%s", diff)
	}
}

func TestLinux_clientBSSMissingBSSAttributeIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// One message without BSS attribute
		return []genetlink.Message{{
			Header: genetlink.Header{
				Command: unix.NL80211_CMD_NEW_SCAN_RESULTS,
			},
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: unix.NL80211_ATTR_IFINDEX,
				Data: nlenc.Uint32Bytes(1),
			}}),
		}}, nil
	})

	_, err := c.BSS(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientBSSMissingBSSStatusAttributeIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		return []genetlink.Message{{
			Header: genetlink.Header{
				Command: unix.NL80211_CMD_NEW_SCAN_RESULTS,
			},
			// BSS attribute, but no nested status attribute for the "active" BSS
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: unix.NL80211_ATTR_BSS,
				Data: mustMarshalAttributes([]netlink.Attribute{{
					Type: unix.NL80211_BSS_BSSID,
					Data: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				}}),
			}}),
		}}, nil
	})

	_, err := c.BSS(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientBSSNoMessagesIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// No messages about the BSS at the generic netlink level.
		// Caller will interpret this as no BSS.
		return nil, io.EOF
	})

	_, err := c.BSS(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientBSSOKSkipMissingStatus(t *testing.T) {
	want := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		return []genetlink.Message{
			// Multiple messages, but only second one has BSS status, so the
			// others should be ignored
			{
				Header: genetlink.Header{
					Command: unix.NL80211_CMD_NEW_SCAN_RESULTS,
				},
				Data: mustMarshalAttributes([]netlink.Attribute{{
					Type: unix.NL80211_ATTR_BSS,
					// Does not contain BSS information and status
					Data: mustMarshalAttributes([]netlink.Attribute{{
						Type: unix.NL80211_BSS_BSSID,
						Data: net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
					}}),
				}}),
			},
			{
				Header: genetlink.Header{
					Command: unix.NL80211_CMD_NEW_SCAN_RESULTS,
				},
				Data: mustMarshalAttributes([]netlink.Attribute{{
					Type: unix.NL80211_ATTR_BSS,
					// Contains BSS information and status
					Data: mustMarshalAttributes([]netlink.Attribute{
						{
							Type: unix.NL80211_BSS_BSSID,
							Data: want,
						},
						{
							Type: unix.NL80211_BSS_STATUS,
							Data: nlenc.Uint32Bytes(uint32(BSSStatusAssociated)),
						},
					}),
				}}),
			},
		}, nil
	})

	bss, err := c.BSS(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := bss.BSSID; !bytes.Equal(want, got) {
		t.Fatalf("unexpected BSS BSSID:\n- want: %#v\n-  got: %#v",
			want, got)
	}
}

func TestLinux_clientBSSOK(t *testing.T) {
	want := &BSS{
		SSID:              "Hello, 世界",
		BSSID:             net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		Frequency:         2492,
		BeaconInterval:    100 * 1024 * time.Microsecond,
		LastSeen:          10 * time.Second,
		Status:            BSSStatusAssociated,
		Signal:            -5700,
		SignalUnspecified: 80,
	}

	ifi := &Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	}

	const flags = netlink.Request | netlink.Dump

	msgsFn := mustMessages(t, unix.NL80211_CMD_NEW_SCAN_RESULTS, want)

	c := testClient(t, genltest.CheckRequest(familyID, unix.NL80211_CMD_GET_SCAN, flags,
		func(greq genetlink.Message, nreq netlink.Message) ([]genetlink.Message, error) {
			// Also verify that the correct interface attributes are
			// present in the request.
			attrs, err := netlink.UnmarshalAttributes(greq.Data)
			if err != nil {
				t.Fatalf("failed to unmarshal attributes: %v", err)
			}

			if diff := diffNetlinkAttributes(ifi.idAttrs(), attrs); diff != "" {
				t.Fatalf("unexpected request netlink attributes (-want +got):\n%s", diff)
			}

			return msgsFn(greq, nreq)
		},
	))

	got, err := c.BSS(ifi)
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected BSS:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestLinux_clientStationInfoMissingAttributeIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// One message without station info attribute
		return []genetlink.Message{{
			Header: genetlink.Header{
				Command: unix.NL80211_CMD_NEW_STATION,
			},
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: unix.NL80211_ATTR_IFINDEX,
				Data: nlenc.Uint32Bytes(1),
			}}),
		}}, nil
	})

	_, err := c.StationInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientStationInfoNoMessagesIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// No messages about station info at the generic netlink level.
		// Caller will interpret this as no station info.
		return nil, io.EOF
	})

	info, err := c.StationInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if err != nil {
		t.Fatalf("undexpected error: %v", err)
	}
	if !reflect.DeepEqual(info, []*StationInfo{}) {
		t.Fatalf("expected info to be an empty slice, got %v", info)
	}
}

func TestLinux_clientStationInfoOK(t *testing.T) {
	want := []*StationInfo{
		{
			InterfaceIndex:     1,
			HardwareAddr:       net.HardwareAddr{0xb8, 0x27, 0xeb, 0xd5, 0xf3, 0xef},
			Connected:          30 * time.Minute,
			Inactive:           4 * time.Millisecond,
			ReceivedBytes:      1000,
			TransmittedBytes:   2000,
			ReceivedPackets:    10,
			TransmittedPackets: 20,
			Signal:             -50,
			SignalAverage:      -53,
			TransmitRetries:    5,
			TransmitFailed:     2,
			BeaconLoss:         3,
			ReceiveBitrate:     130000000,
			TransmitBitrate:    130000000,
		},
		{
			InterfaceIndex:     1,
			HardwareAddr:       net.HardwareAddr{0x40, 0xa5, 0xef, 0xd9, 0x96, 0x6f},
			Connected:          60 * time.Minute,
			Inactive:           8 * time.Millisecond,
			ReceivedBytes:      2000,
			TransmittedBytes:   4000,
			ReceivedPackets:    20,
			TransmittedPackets: 40,
			Signal:             -25,
			SignalAverage:      -27,
			TransmitRetries:    10,
			TransmitFailed:     4,
			BeaconLoss:         6,
			ReceiveBitrate:     260000000,
			TransmitBitrate:    260000000,
		},
	}

	ifi := &Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	}

	const flags = netlink.Request | netlink.Dump

	msgsFn := mustMessages(t, unix.NL80211_CMD_NEW_STATION, want)

	c := testClient(t, genltest.CheckRequest(familyID, unix.NL80211_CMD_GET_STATION, flags,
		func(greq genetlink.Message, nreq netlink.Message) ([]genetlink.Message, error) {
			// Also verify that the correct interface attributes are
			// present in the request.
			attrs, err := netlink.UnmarshalAttributes(greq.Data)
			if err != nil {
				t.Fatalf("failed to unmarshal attributes: %v", err)
			}

			if diff := diffNetlinkAttributes(ifi.idAttrs(), attrs); diff != "" {
				t.Fatalf("unexpected request netlink attributes (-want +got):\n%s", diff)
			}

			return msgsFn(greq, nreq)
		},
	))

	got, err := c.StationInfo(ifi)
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	for i := range want {
		if !reflect.DeepEqual(want[i], got[i]) {
			t.Fatalf("unexpected station info:\n- want: %v\n-  got: %v",
				want[i], got[i])
		}
	}
}

func TestLinux_initClientErrorCloseConn(t *testing.T) {
	c := genltest.Dial(func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// Assume that nl80211 does not exist on this system.
		// The genetlink Conn should be closed to avoid leaking file descriptors.
		return nil, genltest.Error(int(syscall.ENOENT))
	})

	if _, err := initClient(c); err == nil {
		t.Fatal("no error occurred, but expected one")
	}
}

const familyID = 26

func testClient(t *testing.T, fn genltest.Func) *client {
	family := genetlink.Family{
		ID:      familyID,
		Name:    unix.NL80211_GENL_NAME,
		Version: 1,
	}

	c := genltest.Dial(genltest.ServeFamily(family, func(greq genetlink.Message, nreq netlink.Message) ([]genetlink.Message, error) {
		// If this function is invoked, we are calling a nl80211 function.
		if diff := cmp.Diff(int(family.ID), int(nreq.Header.Type)); diff != "" {
			t.Fatalf("unexpected generic netlink family ID (-want +got):\n%s", diff)
		}

		if diff := cmp.Diff(family.Version, greq.Header.Version); diff != "" {
			t.Fatalf("unexpected generic netlink family version (-want +got):\n%s", diff)
		}

		msgs, err := fn(greq, nreq)
		if err != nil {
			return nil, err
		}

		// Do a favor for the caller by planting the correct version in each message
		// header, as long as no version is supplied.
		for i := range msgs {
			if msgs[i].Header.Version == 0 {
				msgs[i].Header.Version = family.Version
			}
		}

		return msgs, nil
	}))

	client, err := initClient(c)
	if err != nil {
		t.Fatalf("failed to initialize test client: %v", err)
	}

	return client
}

// diffNetlinkAttributes compares two []netlink.Attributes after zeroing their
// length fields that make equality checks in testing difficult.
func diffNetlinkAttributes(want, got []netlink.Attribute) string {
	// If different lengths, diff immediately for better error output.
	if len(want) != len(got) {
		return cmp.Diff(want, got)
	}

	for i := range want {
		want[i].Length = 0
		got[i].Length = 0
	}

	return cmp.Diff(want, got)
}

// Helper functions for converting types back into their raw attribute formats

func marshalIEs(ies []ie) []byte {
	buf := bytes.NewBuffer(nil)
	for _, ie := range ies {
		buf.WriteByte(ie.ID)
		buf.WriteByte(uint8(len(ie.Data)))
		buf.Write(ie.Data)
	}

	return buf.Bytes()
}

func mustMarshalAttributes(attrs []netlink.Attribute) []byte {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal attributes: %v", err))
	}

	return b
}

type attributeser interface {
	attributes() []netlink.Attribute
}

var (
	_ attributeser = &Interface{}
	_ attributeser = &BSS{}
	_ attributeser = &StationInfo{}
)

func (ifi *Interface) attributes() []netlink.Attribute {
	return []netlink.Attribute{
		{Type: unix.NL80211_ATTR_IFINDEX, Data: nlenc.Uint32Bytes(uint32(ifi.Index))},
		{Type: unix.NL80211_ATTR_IFNAME, Data: nlenc.Bytes(ifi.Name)},
		{Type: unix.NL80211_ATTR_MAC, Data: ifi.HardwareAddr},
		{Type: unix.NL80211_ATTR_WIPHY, Data: nlenc.Uint32Bytes(uint32(ifi.PHY))},
		{Type: unix.NL80211_ATTR_IFTYPE, Data: nlenc.Uint32Bytes(uint32(ifi.Type))},
		{Type: unix.NL80211_ATTR_WDEV, Data: nlenc.Uint64Bytes(uint64(ifi.Device))},
		{Type: unix.NL80211_ATTR_WIPHY_FREQ, Data: nlenc.Uint32Bytes(uint32(ifi.Frequency))},
	}
}

func (b *BSS) attributes() []netlink.Attribute {
	return []netlink.Attribute{
		// TODO(mdlayher): return more attributes for validation?
		{
			Type: unix.NL80211_ATTR_BSS,
			Data: mustMarshalAttributes([]netlink.Attribute{
				{Type: unix.NL80211_BSS_BSSID, Data: b.BSSID},
				{Type: unix.NL80211_BSS_FREQUENCY, Data: nlenc.Uint32Bytes(uint32(b.Frequency))},
				{Type: unix.NL80211_BSS_BEACON_INTERVAL, Data: nlenc.Uint16Bytes(uint16(b.BeaconInterval / 1024 / time.Microsecond))},
				{Type: unix.NL80211_BSS_SEEN_MS_AGO, Data: nlenc.Uint32Bytes(uint32(b.LastSeen / time.Millisecond))},
				{Type: unix.NL80211_BSS_STATUS, Data: nlenc.Uint32Bytes(uint32(b.Status))},
				{Type: unix.NL80211_BSS_SIGNAL_MBM, Data: nlenc.Int32Bytes(int32(b.Signal))},
				{Type: unix.NL80211_BSS_SIGNAL_UNSPEC, Data: nlenc.Uint32Bytes(uint32(b.SignalUnspecified))},
				{
					Type: unix.NL80211_BSS_INFORMATION_ELEMENTS,
					Data: marshalIEs([]ie{{
						ID:   ieSSID,
						Data: []byte(b.SSID),
					}}),
				},
			}),
		},
	}
}

func (s *StationInfo) attributes() []netlink.Attribute {
	return []netlink.Attribute{
		// TODO(mdlayher): return more attributes for validation?
		{
			Type: unix.NL80211_ATTR_MAC,
			Data: s.HardwareAddr,
		},
		{
			Type: unix.NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(s.InterfaceIndex)),
		},
		{
			Type: unix.NL80211_ATTR_STA_INFO,
			Data: mustMarshalAttributes([]netlink.Attribute{
				{Type: unix.NL80211_STA_INFO_CONNECTED_TIME, Data: nlenc.Uint32Bytes(uint32(s.Connected.Seconds()))},
				{Type: unix.NL80211_STA_INFO_INACTIVE_TIME, Data: nlenc.Uint32Bytes(uint32(s.Inactive.Seconds() * 1000))},
				{Type: unix.NL80211_STA_INFO_RX_BYTES, Data: nlenc.Uint32Bytes(uint32(s.ReceivedBytes))},
				{Type: unix.NL80211_STA_INFO_RX_BYTES64, Data: nlenc.Uint64Bytes(uint64(s.ReceivedBytes))},
				{Type: unix.NL80211_STA_INFO_TX_BYTES, Data: nlenc.Uint32Bytes(uint32(s.TransmittedBytes))},
				{Type: unix.NL80211_STA_INFO_TX_BYTES64, Data: nlenc.Uint64Bytes(uint64(s.TransmittedBytes))},
				{Type: unix.NL80211_STA_INFO_SIGNAL, Data: []byte{byte(int8(s.Signal))}},
				{Type: unix.NL80211_STA_INFO_SIGNAL_AVG, Data: []byte{byte(int8(s.SignalAverage))}},
				{Type: unix.NL80211_STA_INFO_RX_PACKETS, Data: nlenc.Uint32Bytes(uint32(s.ReceivedPackets))},
				{Type: unix.NL80211_STA_INFO_TX_PACKETS, Data: nlenc.Uint32Bytes(uint32(s.TransmittedPackets))},
				{Type: unix.NL80211_STA_INFO_TX_RETRIES, Data: nlenc.Uint32Bytes(uint32(s.TransmitRetries))},
				{Type: unix.NL80211_STA_INFO_TX_FAILED, Data: nlenc.Uint32Bytes(uint32(s.TransmitFailed))},
				{Type: unix.NL80211_STA_INFO_BEACON_LOSS, Data: nlenc.Uint32Bytes(uint32(s.BeaconLoss))},
				{
					Type: unix.NL80211_STA_INFO_RX_BITRATE,
					Data: mustMarshalAttributes([]netlink.Attribute{
						{Type: unix.NL80211_RATE_INFO_BITRATE, Data: nlenc.Uint16Bytes(uint16(bitrateAttr(s.ReceiveBitrate)))},
						{Type: unix.NL80211_RATE_INFO_BITRATE32, Data: nlenc.Uint32Bytes(bitrateAttr(s.ReceiveBitrate))},
					}),
				},
				{
					Type: unix.NL80211_STA_INFO_TX_BITRATE,
					Data: mustMarshalAttributes([]netlink.Attribute{
						{Type: unix.NL80211_RATE_INFO_BITRATE, Data: nlenc.Uint16Bytes(uint16(bitrateAttr(s.TransmitBitrate)))},
						{Type: unix.NL80211_RATE_INFO_BITRATE32, Data: nlenc.Uint32Bytes(bitrateAttr(s.TransmitBitrate))},
					}),
				},
			}),
		},
	}
}

func (s *SurveyInfo) attributes() []netlink.Attribute {
	attributes := []netlink.Attribute{
		{Type: unix.NL80211_SURVEY_INFO_FREQUENCY, Data: nlenc.Uint32Bytes(uint32(s.Frequency))},
		{Type: unix.NL80211_SURVEY_INFO_NOISE, Data: []byte{byte(int8(s.Noise))}},
	}
	if s.InUse {
		attributes = append(attributes, netlink.Attribute{Type: unix.NL80211_SURVEY_INFO_IN_USE})
	}
	attributes = append(attributes, []netlink.Attribute{
		{Type: unix.NL80211_SURVEY_INFO_TIME, Data: nlenc.Uint64Bytes(uint64(s.ChannelTime / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_BUSY, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeBusy / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_EXT_BUSY, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeExtBusy / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_BSS_RX, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeBssRx / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_RX, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeRx / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_TX, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeTx / time.Millisecond))},
		{Type: unix.NL80211_SURVEY_INFO_TIME_SCAN, Data: nlenc.Uint64Bytes(uint64(s.ChannelTimeScan / time.Millisecond))},
	}...)
	return []netlink.Attribute{
		{
			Type: unix.NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(s.InterfaceIndex)),
		},
		{
			Type: unix.NL80211_ATTR_SURVEY_INFO,
			Data: mustMarshalAttributes(attributes),
		},
	}
}

func bitrateAttr(bitrate int) uint32 {
	return uint32(bitrate / 100 / 1000)
}

func mustMessages(t *testing.T, command uint8, want interface{}) genltest.Func {
	var as []attributeser

	switch xs := want.(type) {
	case []*Interface:
		for _, x := range xs {
			as = append(as, x)
		}
	case *BSS:
		as = append(as, xs)

	case []*StationInfo:
		for _, x := range xs {
			as = append(as, x)
		}
	case []*SurveyInfo:
		for _, x := range xs {
			as = append(as, x)
		}
	default:
		t.Fatalf("cannot make messages for type: %T", xs)
	}

	msgs := make([]genetlink.Message, 0, len(as))
	for _, a := range as {
		msgs = append(msgs, genetlink.Message{
			Header: genetlink.Header{
				Command: command,
			},
			Data: mustMarshalAttributes(a.attributes()),
		})
	}

	return func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		return msgs, nil
	}
}

func Test_decodeBSSLoad(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name                           string
		args                           args
		wantVersion                    uint16
		wantStationCount               uint16
		wantChannelUtilization         uint8
		wantAvailableAdmissionCapacity uint16
	}{
		{name: "Parse BSS Load Normal", args: args{b: []byte{3, 0, 8, 0x8D, 0x5B}}, wantVersion: 2, wantStationCount: 3, wantChannelUtilization: 8, wantAvailableAdmissionCapacity: 23437},
		{name: "Parse BSS Load Version 1", args: args{b: []byte{9, 0, 8, 0x8D}}, wantVersion: 1, wantStationCount: 9, wantChannelUtilization: 8, wantAvailableAdmissionCapacity: 141},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bssLoad, _ := decodeBSSLoad(tt.args.b)
			gotVersion := bssLoad.Version
			gotStationCount := bssLoad.StationCount
			gotChannelUtilization := bssLoad.ChannelUtilization
			gotAvailableAdmissionCapacity := bssLoad.AvailableAdmissionCapacity
			if uint16(gotVersion) != tt.wantVersion {
				t.Errorf("decodeBSSLoad() gotVersion = %v, want %v", gotVersion, tt.wantVersion)
			}
			if gotStationCount != tt.wantStationCount {
				t.Errorf("decodeBSSLoad() gotStationCount = %v, want %v", gotStationCount, tt.wantStationCount)
			}
			if gotChannelUtilization != tt.wantChannelUtilization {
				t.Errorf("decodeBSSLoad() gotChannelUtilization = %v, want %v", gotChannelUtilization, tt.wantChannelUtilization)
			}
			if gotAvailableAdmissionCapacity != tt.wantAvailableAdmissionCapacity {
				t.Errorf("decodeBSSLoad() gotAvailableAdmissionCapacity = %v, want %v", gotAvailableAdmissionCapacity, tt.wantAvailableAdmissionCapacity)
			}
		})
	}
}

func Test_decodeBSSLoadError(t *testing.T) {
	t.Parallel()
	_, err := decodeBSSLoad([]byte{3, 0, 8})
	if err == nil {
		t.Error("want error on bogus IE with wrong length")
	}
}

func TestLinux_clientSurveryInfoMissingAttributeIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// One message without station info attribute
		return []genetlink.Message{{
			Header: genetlink.Header{
				Command: unix.NL80211_CMD_GET_SURVEY,
			},
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: unix.NL80211_ATTR_IFINDEX,
				Data: nlenc.Uint32Bytes(1),
			}}),
		}}, nil
	})

	_, err := c.StationInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientSurveyInfoNoMessagesIsNotExist(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// No messages about station info at the generic netlink level.
		// Caller will interpret this as no station info.
		return nil, io.EOF
	})

	info, err := c.SurveyInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if err != nil {
		t.Fatalf("undexpected error: %v", err)
	}
	if !reflect.DeepEqual(info, []*SurveyInfo{}) {
		t.Fatalf("expected info to be an empty slice, got %v", info)
	}
}

func TestLinux_clientSurveyInfoOK(t *testing.T) {
	want := []*SurveyInfo{
		{
			InterfaceIndex:     1,
			Frequency:          2412,
			Noise:              -95,
			InUse:              true,
			ChannelTime:        100 * time.Millisecond,
			ChannelTimeBusy:    50 * time.Millisecond,
			ChannelTimeExtBusy: 10 * time.Millisecond,
			ChannelTimeBssRx:   20 * time.Millisecond,
			ChannelTimeRx:      30 * time.Millisecond,
			ChannelTimeTx:      40 * time.Millisecond,
			ChannelTimeScan:    5 * time.Millisecond,
		},
		{
			InterfaceIndex:     1,
			Frequency:          2437,
			Noise:              -90,
			InUse:              false,
			ChannelTime:        200 * time.Millisecond,
			ChannelTimeBusy:    100 * time.Millisecond,
			ChannelTimeExtBusy: 20 * time.Millisecond,
			ChannelTimeBssRx:   40 * time.Millisecond,
			ChannelTimeRx:      60 * time.Millisecond,
			ChannelTimeTx:      80 * time.Millisecond,
			ChannelTimeScan:    10 * time.Millisecond,
		},
	}

	ifi := &Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	}

	const flags = netlink.Request | netlink.Dump

	msgsFn := mustMessages(t, unix.NL80211_CMD_GET_SURVEY, want)

	c := testClient(t, genltest.CheckRequest(familyID, unix.NL80211_CMD_GET_SURVEY, flags,
		func(greq genetlink.Message, nreq netlink.Message) ([]genetlink.Message, error) {
			// Also verify that the correct interface attributes are
			// present in the request.
			attrs, err := netlink.UnmarshalAttributes(greq.Data)
			if err != nil {
				t.Fatalf("failed to unmarshal attributes: %v", err)
			}

			if diff := diffNetlinkAttributes(ifi.idAttrs(), attrs); diff != "" {
				t.Fatalf("unexpected request netlink attributes (-want +got):\n%s", diff)
			}

			return msgsFn(greq, nreq)
		},
	))

	got, err := c.SurveyInfo(ifi)
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	for i := range want {
		if !reflect.DeepEqual(want[i], got[i]) {
			t.Fatalf("unexpected station info:\n- want: %v\n-  got: %v",
				want[i], got[i])
		}
	}
}

// Test data helpers for decodeRSN tests
func buildRSNIE(parts ...[]byte) []byte {
	var result []byte
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}

var (
	rsnVersion1      = []byte{0x01, 0x00}
	rsnVersion2      = []byte{0x02, 0x00}
	ccmp128Cipher    = []byte{0x00, 0x0F, 0xAC, 0x04}
	tkipCipher       = []byte{0x00, 0x0F, 0xAC, 0x02}
	bipCmac128Cipher = []byte{0x00, 0x0F, 0xAC, 0x06}
	pskAKM           = []byte{0x00, 0x0F, 0xAC, 0x02}
	saeAKM           = []byte{0x00, 0x0F, 0xAC, 0x08}
	dot1xAKM         = []byte{0x00, 0x0F, 0xAC, 0x01}
	oneCipherCount   = []byte{0x01, 0x00}
	twoCipherCount   = []byte{0x02, 0x00}
	zeroCount        = []byte{0x00, 0x00}
	pmfCapable       = []byte{0x80, 0x00}
	pmfRequired      = []byte{0xC0, 0x00}
	pmkid16Bytes     = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
)

// Test valid RSN cases
func Test_decodeRSN_ValidCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *RSNInfo
	}{
		{
			name:  "minimal valid RSN",
			input: buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{},
			},
		},
		{
			name:  "complete RSN with AKMs and capabilities",
			input: buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, oneCipherCount, pskAKM, pmfCapable),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSNAkmPSK},
				Capabilities:    0x0080,
			},
		},
		{
			name:  "multiple pairwise ciphers and AKMs",
			input: buildRSNIE(rsnVersion1, tkipCipher, twoCipherCount, tkipCipher, ccmp128Cipher, twoCipherCount, dot1xAKM, pskAKM),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherTKIP,
				PairwiseCiphers: []RSNCipher{RSNCipherTKIP, RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSNAkm8021X, RSNAkmPSK},
			},
		},
		{
			name:  "with group management cipher (WPA3/802.11w)",
			input: buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, oneCipherCount, saeAKM, pmfRequired, zeroCount, bipCmac128Cipher),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSNAkmSAE},
				Capabilities:    0x00C0,
				GroupMgmtCipher: RSNCipherBIPCMAC128,
			},
		},
		{
			name:  "with PMKID list",
			input: buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, oneCipherCount, pskAKM, zeroCount, oneCipherCount, pmkid16Bytes),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSNAkmPSK},
			},
		},
		{
			name:  "version 2 (should be accepted)",
			input: buildRSNIE(rsnVersion2, ccmp128Cipher, oneCipherCount, ccmp128Cipher),
			expected: &RSNInfo{
				Version:         2,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{},
			},
		},
		{
			name:  "unknown cipher and AKM values",
			input: buildRSNIE(rsnVersion1, []byte{0xFF, 0xFF, 0xFF, 0xFF}, oneCipherCount, []byte{0xAA, 0xBB, 0xCC, 0xDD}, oneCipherCount, []byte{0x11, 0x22, 0x33, 0x44}),
			expected: &RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipher(0xFFFFFFFF),
				PairwiseCiphers: []RSNCipher{RSNCipher(0xAABBCCDD)},
				AKMs:            []RSNAKM{RSNAKM(0x11223344)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidRSN(t, tt.input, tt.expected)
		})
	}
}

// Test RSN error cases
func Test_decodeRSN_ErrorCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *RSNInfo
		errMsg   string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: &RSNInfo{},
			errMsg:   "RSN IE parsing error: IE too short",
		},
		{
			name:     "too short - less than minimum 8 bytes",
			input:    []byte{0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01},
			expected: &RSNInfo{},
			errMsg:   "RSN IE parsing error: IE too short",
		},
		{
			name:     "version 0 (invalid)",
			input:    []byte{0x00, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00},
			expected: &RSNInfo{Version: 0},
			errMsg:   "RSN IE parsing error: invalid version 0",
		},
		{
			name:     "truncated before pairwise count",
			input:    buildRSNIE(rsnVersion1, ccmp128Cipher),
			expected: &RSNInfo{},
			errMsg:   "RSN IE parsing error: IE too short",
		},
		{
			name:     "IE data exceeds maximum size",
			input:    make([]byte, 254),
			expected: &RSNInfo{},
			errMsg:   "RSN IE parsing error: data exceeds maximum size of 253 octets",
		},
	}

	// Initialize the oversized test case
	tests[4].input[0] = 0x01 // version

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRSNError(t, tt.input, tt.expected, tt.errMsg)
		})
	}
}

// Test RSN truncation errors (streamlined)
func Test_decodeRSN_TruncationErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *RSNInfo
		errMsg   string
	}{
		{
			name:     "truncated in pairwise list",
			input:    buildRSNIE(rsnVersion1, ccmp128Cipher, twoCipherCount, ccmp128Cipher),
			expected: &RSNInfo{Version: 1, GroupCipher: RSNCipherCCMP128},
			errMsg:   "RSN IE parsing error: truncated in pairwise list",
		},
		{
			name:     "truncated in AKM list",
			input:    buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, twoCipherCount, dot1xAKM),
			expected: &RSNInfo{Version: 1, GroupCipher: RSNCipherCCMP128, PairwiseCiphers: []RSNCipher{RSNCipherCCMP128}},
			errMsg:   "RSN IE parsing error: truncated in AKM list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRSNError(t, tt.input, tt.expected, tt.errMsg)
		})
	}
}

// Test RSN count validation and edge cases
func Test_decodeRSN_CountValidation(t *testing.T) {
	t.Run("count errors", func(t *testing.T) {
		tests := []struct {
			name     string
			input    []byte
			expected *RSNInfo
			errMsg   string
		}{
			{
				name:     "pairwise cipher count too large",
				input:    buildRSNIE(rsnVersion1, ccmp128Cipher, []byte{0xFF, 0x00}),
				expected: &RSNInfo{Version: 1, GroupCipher: RSNCipherCCMP128},
				errMsg:   "RSN IE parsing error: pairwise cipher count too large",
			},
			{
				name:     "AKM count too large",
				input:    buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, []byte{0xFF, 0x00}),
				expected: &RSNInfo{Version: 1, GroupCipher: RSNCipherCCMP128, PairwiseCiphers: []RSNCipher{RSNCipherCCMP128}},
				errMsg:   "RSN IE parsing error: AKM count too large",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assertRSNError(t, tt.input, tt.expected, tt.errMsg)
			})
		}
	})

	t.Run("zero counts (valid)", func(t *testing.T) {
		tests := []struct {
			name  string
			input []byte
		}{
			{"zero pairwise cipher count", buildRSNIE(rsnVersion1, ccmp128Cipher, zeroCount)},
			{"zero AKM count", buildRSNIE(rsnVersion1, ccmp128Cipher, oneCipherCount, ccmp128Cipher, zeroCount)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := decodeRSN(tt.input)
				if err != nil {
					t.Errorf("decodeRSN() failed: %v", err)
				}
				if got.Version != 1 {
					t.Errorf("decodeRSN() version = %v, want 1", got.Version)
				}
			})
		}
	})
}

// compareRSNCipherSlices compares two RSNCipher slices, treating nil and empty slices as equal
func compareRSNCipherSlices(a, b []RSNCipher) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// compareRSNAKMSlices compares two RSNAKM slices, treating nil and empty slices as equal
func compareRSNAKMSlices(a, b []RSNAKM) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// Helper assertion functions for RSN tests
func assertValidRSN(t *testing.T, input []byte, expected *RSNInfo) {
	t.Helper()
	got, err := decodeRSN(input)
	if err != nil {
		t.Errorf("decodeRSN() unexpected error = %v", err)
		return
	}

	// Compare individual fields
	if got.Version != expected.Version {
		t.Errorf("decodeRSN() version = %v, want %v", got.Version, expected.Version)
	}
	if got.GroupCipher != expected.GroupCipher {
		t.Errorf("decodeRSN() group cipher = %v, want %v", got.GroupCipher, expected.GroupCipher)
	}
	if !compareRSNCipherSlices(got.PairwiseCiphers, expected.PairwiseCiphers) {
		t.Errorf("decodeRSN() pairwise ciphers = %v, want %v", got.PairwiseCiphers, expected.PairwiseCiphers)
	}
	if !compareRSNAKMSlices(got.AKMs, expected.AKMs) {
		t.Errorf("decodeRSN() AKMs = %v, want %v", got.AKMs, expected.AKMs)
	}
	if got.Capabilities != expected.Capabilities {
		t.Errorf("decodeRSN() capabilities = %v, want %v", got.Capabilities, expected.Capabilities)
	}
	if got.GroupMgmtCipher != expected.GroupMgmtCipher {
		t.Errorf("decodeRSN() group mgmt cipher = %v, want %v", got.GroupMgmtCipher, expected.GroupMgmtCipher)
	}
}

func assertRSNError(t *testing.T, input []byte, expected *RSNInfo, errMsg string) {
	t.Helper()
	got, err := decodeRSN(input)
	if err == nil {
		t.Errorf("decodeRSN() expected error but got none")
		return
	}
	if errMsg != "" && err.Error() != errMsg {
		t.Errorf("decodeRSN() error = %v, want %v", err.Error(), errMsg)
	}

	// For error cases, check partial parsing results
	if got.Version != expected.Version {
		t.Errorf("decodeRSN() version = %v, want %v", got.Version, expected.Version)
	}
	if got.GroupCipher != expected.GroupCipher {
		t.Errorf("decodeRSN() group cipher = %v, want %v", got.GroupCipher, expected.GroupCipher)
	}
}
