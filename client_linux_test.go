//+build linux

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
	"github.com/mdlayher/wifi/internal/nl80211"
)

func TestLinux_clientInterfacesBadResponseCommand(t *testing.T) {
	c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		return []genetlink.Message{{
			Header: genetlink.Header{
				// Wrong response command
				Command: nl80211.CmdGetInterface,
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
				Command: nl80211.CmdNewInterface,
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

	c := testClient(t, genltest.CheckRequest(familyID, nl80211.CmdGetInterface, flags,
		mustMessages(t, nl80211.CmdNewInterface, want),
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
				Command: nl80211.CmdNewScanResults,
			},
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: nl80211.AttrIfindex,
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
				Command: nl80211.CmdNewScanResults,
			},
			// BSS attribute, but no nested status attribute for the "active" BSS
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: nl80211.AttrBss,
				Data: mustMarshalAttributes([]netlink.Attribute{{
					Type: nl80211.BssBssid,
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
					Command: nl80211.CmdNewScanResults,
				},
				Data: mustMarshalAttributes([]netlink.Attribute{{
					Type: nl80211.AttrBss,
					// Does not contain BSS information and status
					Data: mustMarshalAttributes([]netlink.Attribute{{
						Type: nl80211.BssBssid,
						Data: net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
					}}),
				}}),
			},
			{
				Header: genetlink.Header{
					Command: nl80211.CmdNewScanResults,
				},
				Data: mustMarshalAttributes([]netlink.Attribute{{
					Type: nl80211.AttrBss,
					// Contains BSS information and status
					Data: mustMarshalAttributes([]netlink.Attribute{
						{
							Type: nl80211.BssBssid,
							Data: want,
						},
						{
							Type: nl80211.BssStatus,
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

	msgsFn := mustMessages(t, nl80211.CmdNewScanResults, want)

	c := testClient(t, genltest.CheckRequest(familyID, nl80211.CmdGetScan, flags,
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
				Command: nl80211.CmdNewStation,
			},
			Data: mustMarshalAttributes([]netlink.Attribute{{
				Type: nl80211.AttrIfindex,
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

	msgsFn := mustMessages(t, nl80211.CmdNewStation, want)

	c := testClient(t, genltest.CheckRequest(familyID, nl80211.CmdGetStation, flags,
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
		Name:    nl80211.GenlName,
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
		{Type: nl80211.AttrIfindex, Data: nlenc.Uint32Bytes(uint32(ifi.Index))},
		{Type: nl80211.AttrIfname, Data: nlenc.Bytes(ifi.Name)},
		{Type: nl80211.AttrMac, Data: ifi.HardwareAddr},
		{Type: nl80211.AttrWiphy, Data: nlenc.Uint32Bytes(uint32(ifi.PHY))},
		{Type: nl80211.AttrIftype, Data: nlenc.Uint32Bytes(uint32(ifi.Type))},
		{Type: nl80211.AttrWdev, Data: nlenc.Uint64Bytes(uint64(ifi.Device))},
		{Type: nl80211.AttrWiphyFreq, Data: nlenc.Uint32Bytes(uint32(ifi.Frequency))},
	}
}

func (b *BSS) attributes() []netlink.Attribute {
	return []netlink.Attribute{
		// TODO(mdlayher): return more attributes for validation?
		{
			Type: nl80211.AttrBss,
			Data: mustMarshalAttributes([]netlink.Attribute{
				{Type: nl80211.BssBssid, Data: b.BSSID},
				{Type: nl80211.BssFrequency, Data: nlenc.Uint32Bytes(uint32(b.Frequency))},
				{Type: nl80211.BssBeaconInterval, Data: nlenc.Uint16Bytes(uint16(b.BeaconInterval / 1024 / time.Microsecond))},
				{Type: nl80211.BssSeenMsAgo, Data: nlenc.Uint32Bytes(uint32(b.LastSeen / time.Millisecond))},
				{Type: nl80211.BssStatus, Data: nlenc.Uint32Bytes(uint32(b.Status))},
				{
					Type: nl80211.BssInformationElements,
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
			Type: nl80211.AttrMac,
			Data: s.HardwareAddr,
		},
		{
			Type: nl80211.AttrStaInfo,
			Data: mustMarshalAttributes([]netlink.Attribute{
				{Type: nl80211.StaInfoConnectedTime, Data: nlenc.Uint32Bytes(uint32(s.Connected.Seconds()))},
				{Type: nl80211.StaInfoInactiveTime, Data: nlenc.Uint32Bytes(uint32(s.Inactive.Seconds() * 1000))},
				{Type: nl80211.StaInfoRxBytes, Data: nlenc.Uint32Bytes(uint32(s.ReceivedBytes))},
				{Type: nl80211.StaInfoRxBytes64, Data: nlenc.Uint64Bytes(uint64(s.ReceivedBytes))},
				{Type: nl80211.StaInfoTxBytes, Data: nlenc.Uint32Bytes(uint32(s.TransmittedBytes))},
				{Type: nl80211.StaInfoTxBytes64, Data: nlenc.Uint64Bytes(uint64(s.TransmittedBytes))},
				{Type: nl80211.StaInfoSignal, Data: []byte{byte(int8(s.Signal))}},
				{Type: nl80211.StaInfoRxPackets, Data: nlenc.Uint32Bytes(uint32(s.ReceivedPackets))},
				{Type: nl80211.StaInfoTxPackets, Data: nlenc.Uint32Bytes(uint32(s.TransmittedPackets))},
				{Type: nl80211.StaInfoTxRetries, Data: nlenc.Uint32Bytes(uint32(s.TransmitRetries))},
				{Type: nl80211.StaInfoTxFailed, Data: nlenc.Uint32Bytes(uint32(s.TransmitFailed))},
				{Type: nl80211.StaInfoBeaconLoss, Data: nlenc.Uint32Bytes(uint32(s.BeaconLoss))},
				{
					Type: nl80211.StaInfoRxBitrate,
					Data: mustMarshalAttributes([]netlink.Attribute{
						{Type: nl80211.RateInfoBitrate, Data: nlenc.Uint16Bytes(uint16(bitrateAttr(s.ReceiveBitrate)))},
						{Type: nl80211.RateInfoBitrate32, Data: nlenc.Uint32Bytes(bitrateAttr(s.ReceiveBitrate))},
					}),
				},
				{
					Type: nl80211.StaInfoTxBitrate,
					Data: mustMarshalAttributes([]netlink.Attribute{
						{Type: nl80211.RateInfoBitrate, Data: nlenc.Uint16Bytes(uint16(bitrateAttr(s.TransmitBitrate)))},
						{Type: nl80211.RateInfoBitrate32, Data: nlenc.Uint32Bytes(bitrateAttr(s.TransmitBitrate))},
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
