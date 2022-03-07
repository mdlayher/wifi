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

func TestLinux_clientInterfacesBadResponseCommand(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		return []genetlink.Message{{
			Header: genetlink.Header{
				// Wrong response command
				Command: unix.NL80211_CMD_GET_INTERFACE,
			},
		}}, nil
	})

	want := errInvalidCommand
	_, got := c.Interfaces()

	if want != got {
		t.Fatalf("unexpected error:\n- want: %+v\n-  got: %+v",
			want, got)
	}
}

func TestLinux_clientInterfacesBadResponseFamilyVersion(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		return []genetlink.Message{{
			Header: genetlink.Header{
				// Wrong family version
				Command: unix.NL80211_CMD_NEW_INTERFACE,
				Version: 100,
			},
		}}, nil
	})

	want := errInvalidFamilyVersion
	_, got := c.Interfaces()

	if want != got {
		t.Fatalf("unexpected error:\n- want: %+v\n-  got: %+v",
			want, got)
	}
}

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
		SSID:           "Hello, 世界",
		BSSID:          net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		Frequency:      2492,
		BeaconInterval: 100 * 1024 * time.Microsecond,
		LastSeen:       10 * time.Second,
		Status:         BSSStatusAssociated,
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

	_, err := c.StationInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientStationInfoOK(t *testing.T) {
	want := []*StationInfo{
		{
			HardwareAddr:       net.HardwareAddr{0xb8, 0x27, 0xeb, 0xd5, 0xf3, 0xef},
			Connected:          30 * time.Minute,
			Inactive:           4 * time.Millisecond,
			ReceivedBytes:      1000,
			TransmittedBytes:   2000,
			ReceivedPackets:    10,
			TransmittedPackets: 20,
			Signal:             -50,
			TransmitRetries:    5,
			TransmitFailed:     2,
			BeaconLoss:         3,
			ReceiveBitrate:     130000000,
			TransmitBitrate:    130000000,
		},
		{
			HardwareAddr:       net.HardwareAddr{0x40, 0xa5, 0xef, 0xd9, 0x96, 0x6f},
			Connected:          60 * time.Minute,
			Inactive:           8 * time.Millisecond,
			ReceivedBytes:      2000,
			TransmittedBytes:   4000,
			ReceivedPackets:    20,
			TransmittedPackets: 40,
			Signal:             -25,
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
			Type: unix.NL80211_ATTR_STA_INFO,
			Data: mustMarshalAttributes([]netlink.Attribute{
				{Type: unix.NL80211_STA_INFO_CONNECTED_TIME, Data: nlenc.Uint32Bytes(uint32(s.Connected.Seconds()))},
				{Type: unix.NL80211_STA_INFO_INACTIVE_TIME, Data: nlenc.Uint32Bytes(uint32(s.Inactive.Seconds() * 1000))},
				{Type: unix.NL80211_STA_INFO_RX_BYTES, Data: nlenc.Uint32Bytes(uint32(s.ReceivedBytes))},
				{Type: unix.NL80211_STA_INFO_RX_BYTES64, Data: nlenc.Uint64Bytes(uint64(s.ReceivedBytes))},
				{Type: unix.NL80211_STA_INFO_TX_BYTES, Data: nlenc.Uint32Bytes(uint32(s.TransmittedBytes))},
				{Type: unix.NL80211_STA_INFO_TX_BYTES64, Data: nlenc.Uint64Bytes(uint64(s.TransmittedBytes))},
				{Type: unix.NL80211_STA_INFO_SIGNAL, Data: []byte{byte(int8(s.Signal))}},
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
