//+build linux

package wifi

import (
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/genetlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/wifi/internal/nl80211"
)

func TestLinux_clientInterfacesBadResponseCommand(t *testing.T) {
	msgs := []genetlink.Message{{
		Header: genetlink.Header{
			// Wrong response command
			Command: nl80211.CmdGetInterface,
		},
	}}

	c := testClient(t, msgs, nil)

	want := errInvalidCommand
	_, got := c.Interfaces()

	if want != got {
		t.Fatalf("unexpected error:\n- want: %+v\n-  got: %+v",
			want, got)
	}
}

func TestLinux_clientInterfacesBadResponseFamilyVersion(t *testing.T) {
	msgs := []genetlink.Message{{
		Header: genetlink.Header{
			// Wrong family version
			Command: nl80211.CmdNewInterface,
			Version: 100,
		},
	}}

	c := testClient(t, msgs, nil)

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

	msgs := mustMessages(t, nl80211.CmdNewInterface, want)

	c := testClient(t, msgs, &check{
		Command: nl80211.CmdGetInterface,
		Flags:   netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump,
	})

	got, err := c.Interfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if want, got := derefInterfaces(want), derefInterfaces(got); !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected interfaces:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestLinux_clientStationInfoIsNotExist(t *testing.T) {
	// One message without station info attribute
	msgs := []genetlink.Message{{
		Header: genetlink.Header{
			Command: nl80211.CmdNewStation,
		},
	}}
	c := testClient(t, msgs, nil)

	_, err := c.StationInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})
	if !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, got: %v", err)
	}
}

func TestLinux_clientStationInfoMultipleMessages(t *testing.T) {
	// Multiple messages
	msgs := []genetlink.Message{{}, {}}

	c := testClient(t, msgs, nil)

	want := errMultipleMessages
	_, got := c.StationInfo(&Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	})

	if want != got {
		t.Fatalf("unexpected error:\n- want: %+v\n-  got: %+v",
			want, got)
	}
}

func TestLinux_clientStationInfoOK(t *testing.T) {
	want := &StationInfo{
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
	}

	ifi := &Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0xe, 0xad, 0xbe, 0xef, 0xde, 0xad},
	}

	msgs := mustMessages(t, nl80211.CmdNewStation, want)

	c := testClient(t, msgs, &check{
		Command: nl80211.CmdGetStation,
		Flags:   netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump,
		Attrs:   ifi.stationInfoAttrs(),
	})

	got, err := c.StationInfo(ifi)
	if err != nil {
		log.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected station info:\n- want: %v\n-  got: %v",
			want, got)
	}
}

type check struct {
	Command uint8
	Flags   netlink.HeaderFlags
	Attrs   []netlink.Attribute
}

func testClient(t *testing.T, messages []genetlink.Message, ch *check) *client {
	const (
		familyID      = 10
		familyVersion = 1
	)

	g := &testGENL{
		family: genetlink.Family{
			ID:      familyID,
			Version: familyVersion,
			Name:    nl80211.GenlName,
		},
		messages: messages,
	}

	g.precheck = func(m genetlink.Message, family uint16, flags netlink.HeaderFlags) {
		if want, got := familyID, int(family); want != got {
			t.Fatalf("unexpected family ID:\n- want: %v\n-  got: %v",
				want, got)
		}

		if want, got := familyVersion, int(m.Header.Version); want != got {
			t.Fatalf("unexpected family version:\n- want: %v\n-  got: %v",
				want, got)
		}

		if ch == nil {
			return
		}
		if ch.Attrs == nil {
			ch.Attrs = make([]netlink.Attribute, 0)
		}

		if want, got := ch.Flags, flags; want != got {
			t.Fatalf("unexpected header flags:\n- want: %s\n-  got: %s",
				want, got)
		}

		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			t.Fatalf("failed to unmarshal attributes: %v", err)
		}

		// Zero out length fields since we don't want to have to fill them out
		// in tests
		gotAttrs := make([]netlink.Attribute, 0, len(ch.Attrs))
		for _, a := range attrs {
			a.Length = 0
			gotAttrs = append(gotAttrs, a)
		}

		if want, got := ch.Attrs, gotAttrs; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected attributes:\n- want: %#v\n-  got: %#v",
				want, got)
		}
	}

	c, err := initClient(g)
	if err != nil {
		t.Fatalf("error during client init: %v", err)
	}

	return c
}

var _ genl = &testGENL{}

type testGENL struct {
	family   genetlink.Family
	messages []genetlink.Message

	precheck func(m genetlink.Message, family uint16, flags netlink.HeaderFlags)
}

func (g *testGENL) GetFamily(name string) (genetlink.Family, error) {
	return g.family, nil
}

func (g *testGENL) Execute(m genetlink.Message, family uint16, flags netlink.HeaderFlags) ([]genetlink.Message, error) {
	g.precheck(m, family, flags)

	// Populate response with correct version, if one isn't set
	msgs := make([]genetlink.Message, 0, len(g.messages))
	for _, m := range g.messages {
		if m.Header.Version != 0 {
			msgs = append(msgs, m)
			continue
		}

		m.Header.Version = g.family.Version
		msgs = append(msgs, m)
	}

	return msgs, nil
}

// Helper functions for converting types back into their raw attribute formats

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

func (s *StationInfo) attributes() []netlink.Attribute {
	return []netlink.Attribute{
		// TODO(mdlayher): return more attributes for validation?
		{
			Type: nl80211.AttrStaInfo,
			Data: mustMarshalAttributes([]netlink.Attribute{
				{Type: nl80211.StaInfoConnectedTime, Data: nlenc.Uint32Bytes(uint32(s.Connected.Seconds()))},
				{Type: nl80211.StaInfoInactiveTime, Data: nlenc.Uint32Bytes(uint32(s.Inactive.Seconds() * 1000))},
				{Type: nl80211.StaInfoRxBytes, Data: nlenc.Uint32Bytes(uint32(s.ReceivedBytes))},
				{Type: nl80211.StaInfoRxBytes64, Data: nlenc.Uint64Bytes(s.ReceivedBytes)},
				{Type: nl80211.StaInfoTxBytes, Data: nlenc.Uint32Bytes(uint32(s.TransmittedBytes))},
				{Type: nl80211.StaInfoTxBytes64, Data: nlenc.Uint64Bytes(s.TransmittedBytes)},
				{Type: nl80211.StaInfoSignal, Data: []byte{uint8(s.Signal) + math.MaxUint8}},
				{Type: nl80211.StaInfoRxPackets, Data: nlenc.Uint32Bytes(s.ReceivedPackets)},
				{Type: nl80211.StaInfoTxPackets, Data: nlenc.Uint32Bytes(s.TransmittedPackets)},
				{Type: nl80211.StaInfoTxRetries, Data: nlenc.Uint32Bytes(s.TransmitRetries)},
				{Type: nl80211.StaInfoTxFailed, Data: nlenc.Uint32Bytes(s.TransmitFailed)},
				{Type: nl80211.StaInfoBeaconLoss, Data: nlenc.Uint32Bytes(s.BeaconLoss)},
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

func mustMessages(t *testing.T, command uint8, want interface{}) []genetlink.Message {
	var as []attributeser

	switch xs := want.(type) {
	case []*Interface:
		for _, x := range xs {
			as = append(as, x)
		}
	case *StationInfo:
		as = append(as, xs)
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

	return msgs
}

func derefInterfaces(ifis []*Interface) []Interface {
	out := make([]Interface, 0, len(ifis))
	for _, ifi := range ifis {
		out = append(out, *ifi)
	}

	return out
}
