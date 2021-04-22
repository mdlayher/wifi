//+build linux

package wifi

import (
	"bytes"
	"errors"
	"net"
	"os"
	"time"
	"unicode/utf8"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/howardstark/wifi/internal/nl80211"

)

// Errors which may occur when interacting with generic netlink.
var (
	errMultipleMessages     	 = errors.New("expected only one generic netlink message")
	errInvalidCommand       	 = errors.New("invalid generic netlink response command")
	errInvalidFamilyVersion 	 = errors.New("invalid generic netlink response family version")
	errMissingMulticastGroupScan	 = errors.New("scan multicast group unavailable")
	errScanAborted 			 = errors.New("scan aborted")
)

var _ osClient = &client{}

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type client struct {
	c             *genetlink.Conn
	familyID      uint16
	familyVersion uint8
}

// newClient dials a generic netlink connection and verifies that nl80211
// is available for use by this package.
func newClient() (*client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	return initClient(c)
}

func initClient(c *genetlink.Conn) (*client, error) {
	family, err := c.GetFamily(nl80211.GenlName)
	if err != nil {
		// Ensure the genl socket is closed on error to avoid leaking file
		// descriptors.
		_ = c.Close()
		return nil, err
	}

	return &client{
		c:             c,
		familyID:      family.ID,
		familyVersion: family.Version,
	}, nil
}

// Close closes the client's generic netlink connection.
func (c *client) Close() error {
	return c.c.Close()
}

// Interfaces requests that nl80211 return a list of all WiFi interfaces present
// on this system.
func (c *client) Interfaces() ([]*Interface, error) {
	// Ask nl80211 to dump a list of all WiFi interfaces
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetInterface,
			Version: c.familyVersion,
		},
	}

	flags := netlink.Request | netlink.Dump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewInterface); err != nil {
		return nil, err
	}

	return parseInterfaces(msgs)
}

// BSS requests that nl80211 return the BSS for the specified Interface.
func (c *client) BSS(ifi *Interface) (*BSS, error) {
	b, err := netlink.MarshalAttributes(ifi.idAttrs())
	if err != nil {
		return nil, err
	}

	// Ask nl80211 to retrieve BSS information for the interface specified
	// by its attributes
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetScan,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.Request | netlink.Dump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewScanResults); err != nil {
		return nil, err
	}

	return parseBSS(msgs)
}

<<<<<<< HEAD
func (c *client) ScanAPs(ifi *Interface) ([]*BSS, error) {
	family, err := c.c.GetFamily(nl80211.GenlName)
	if err != nil {
		return nil, err
	}
	var mcastScan genetlink.MulticastGroup
	for _, mcast := range family.Groups {
		if mcast.Name == nl80211.MulticastGroupScan {
			mcastScan = mcast
		}
	}
	if mcastScan.Name != nl80211.MulticastGroupScan {
		return nil, errMissingMulticastGroupScan
	}

	err = c.c.JoinGroup(mcastScan.ID)
	if err != nil {
		return nil, err
	}

	nestedAttrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: nl80211.SchedScanMatchAttrSsid,
			Length: 0,
			Data: nlenc.Bytes(""),
		},
	})
	if err != nil {
		return nil, err
	}

	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: nl80211.AttrScanSsids,
			Nested: true,
			Length: uint16(len(nestedAttrs)),
			Data: nestedAttrs,
		},
		{
			Type: nl80211.AttrIfindex,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
	})
	if err != nil {
		return nil, err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdTriggerScan,
			Version: c.familyVersion,
		},
		Data: attrs,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	for _, m := range msgs {
		if m.Header.Version != c.familyVersion {
			return nil, errInvalidFamilyVersion
		}
		if m.Header.Command == nl80211.CmdScanAborted {
			return nil, errScanAborted
		}
		if m.Header.Command == nl80211.CmdNewScanResults {
			break
		}
	}

	err = c.c.LeaveGroup(mcastScan.ID)
	if err != nil {
		return nil, err
	}

	attrs, err = netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: nl80211.AttrIfindex,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
	})

	if err != nil {
		return nil, err
	}

	req = genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetScan,
			Version: c.familyVersion,
		},
		Data: attrs,
	}

	flags = netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err = c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewScanResults); err != nil {
		return nil, err
	}

	bssm, err := parseBSSMulti(msgs)
	if err != nil {
		return nil, err
	}

	return bssm, nil
}

//func (c *client) SetChannel(ifi *Interface, channel int) error {
//	b, err := netlink.MarshalAttributes(ifi.idAttrs())
//	if err != nil {
//		return err
//	}
//
//	req := genetlink.Message{
//		Header: genetlink.Header{
//			Command: nl80211.CmdSetChannel,
//			Version: c.familyVersion,
//		},
//		Data: b,
//	}
//
//	flags := netlink.HeaderFlagsRequest
//}

// StationInfo requests that nl80211 return all station info for the specified
// Interface.
func (c *client) StationInfo(ifi *Interface) ([]*StationInfo, error) {
	b, err := netlink.MarshalAttributes(ifi.idAttrs())
	if err != nil {
		return nil, err
	}

	// Ask nl80211 to retrieve station info for the interface specified
	// by its attributes
	req := genetlink.Message{
		Header: genetlink.Header{
			// From nl80211.h:
			//  * @NL80211_CMD_GET_STATION: Get station attributes for station identified by
			//  * %NL80211_ATTR_MAC on the interface identified by %NL80211_ATTR_IFINDEX.
			Command: nl80211.CmdGetStation,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.Request | netlink.Dump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if len(msgs) == 0 {
		return nil, os.ErrNotExist
	}

	stations := make([]*StationInfo, len(msgs))
	for i := range msgs {
		if err := c.checkMessages(msgs, nl80211.CmdNewStation); err != nil {
			return nil, err
		}

		if stations[i], err = parseStationInfo(msgs[i].Data); err != nil {
			return nil, err
		}
	}

	return stations, nil
}

// checkMessages verifies that response messages from generic netlink contain
// the command and family version we expect.
func (c *client) checkMessages(msgs []genetlink.Message, command uint8) error {
	for _, m := range msgs {
		if m.Header.Command != command {
			return errInvalidCommand
		}

		if m.Header.Version != c.familyVersion {
			return errInvalidFamilyVersion
		}
	}

	return nil
}

// parseInterfaces parses zero or more Interfaces from nl80211 interface
// messages.
func parseInterfaces(msgs []genetlink.Message) ([]*Interface, error) {
	ifis := make([]*Interface, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var ifi Interface
		if err := (&ifi).parseAttributes(attrs); err != nil {
			return nil, err
		}

		ifis = append(ifis, &ifi)
	}

	return ifis, nil
}

// idAttrs returns the netlink attributes required from an Interface to retrieve
// more data about it.
func (ifi *Interface) idAttrs() []netlink.Attribute {
	return []netlink.Attribute{
		{
			Type: nl80211.AttrIfindex,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
		{
			Type: nl80211.AttrMac,
			Data: ifi.HardwareAddr,
		},
	}
}

// parseAttributes parses netlink attributes into an Interface's fields.
func (ifi *Interface) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.AttrIfindex:
			ifi.Index = int(nlenc.Uint32(a.Data))
		case nl80211.AttrIfname:
			ifi.Name = nlenc.String(a.Data)
		case nl80211.AttrMac:
			ifi.HardwareAddr = net.HardwareAddr(a.Data)
		case nl80211.AttrWiphy:
			ifi.PHY = int(nlenc.Uint32(a.Data))
		case nl80211.AttrIftype:
			// NOTE: InterfaceType copies the ordering of nl80211's interface type
			// constants.  This may not be the case on other operating systems.
			ifi.Type = InterfaceType(nlenc.Uint32(a.Data))
		case nl80211.AttrWdev:
			ifi.Device = int(nlenc.Uint64(a.Data))
		case nl80211.AttrWiphyFreq:
			ifi.Frequency = int(nlenc.Uint32(a.Data))
		}
	}

	return nil
}

// parseBSS parses a single BSS with a status attribute from nl80211 BSS messages.
func parseBSS(msgs []genetlink.Message) (*BSS, error) {
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		for _, a := range attrs {
			if a.Type != nl80211.AttrBss {
				continue
			}

			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			// The BSS which is associated with an interface will have a status
			// attribute
			if !attrsContain(nattrs, nl80211.BssStatus) {
				continue
			}

			var bss BSS
			if err := (&bss).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			return &bss, nil
		}
	}

	return nil, os.ErrNotExist
}

func parseBSSMulti(msgs []genetlink.Message) ([]*BSS, error) {
	bssm := make([]*BSS, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var bss BSS
		if err := (&bss).parseAttributes(attrs); err != nil {
			return nil, err
		}

		bssm = append(bssm, &bss)
	}

	return bssm, nil
}

// parseAttributes parses netlink attributes into a BSS's fields.
func (b *BSS) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.BssBssid:
			b.BSSID = net.HardwareAddr(a.Data)
		case nl80211.BssFrequency:
			b.Frequency = int(nlenc.Uint32(a.Data))
		case nl80211.BssBeaconInterval:
			// Raw value is in "Time Units (TU)".  See:
			// https://en.wikipedia.org/wiki/Beacon_frame
			b.BeaconInterval = time.Duration(nlenc.Uint16(a.Data)) * 1024 * time.Microsecond
		case nl80211.BssSeenMsAgo:
			// * @NL80211_BSS_SEEN_MS_AGO: age of this BSS entry in ms
			b.LastSeen = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case nl80211.BssStatus:
			// NOTE: BSSStatus copies the ordering of nl80211's BSS status
			// constants.  This may not be the case on other operating systems.
			b.Status = BSSStatus(nlenc.Uint32(a.Data))
		case nl80211.BssInformationElements:
			ies, err := parseIEs(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more IEs if they end up being generally useful
			for _, ie := range ies {
				switch ie.ID {
				case ieSSID:
					b.SSID = decodeSSID(ie.Data)
				}
			}
		}
	}

	return nil
}

// parseStationInfo parses StationInfo attributes from a byte slice of
// netlink attributes.
func parseStationInfo(b []byte) (*StationInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info StationInfo
	for _, a := range attrs {

		switch a.Type {
		case nl80211.AttrMac:
			info.HardwareAddr = net.HardwareAddr(a.Data)

		case nl80211.AttrStaInfo:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if err := (&info).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			// nl80211.AttrStaInfo is last attibute we are interested in
			return &info, nil

		default:
			// The other attributes that are returned here appear
			// nl80211.AttrIfindex, nl80211.AttrGeneration
			// No need to parse them for now.
			continue
		}
	}

	// No station info found
	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a StationInfo's fields.
func (info *StationInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.StaInfoConnectedTime:
			// Though nl80211 does not specify, this value appears to be in seconds:
			// * @NL80211_STA_INFO_CONNECTED_TIME: time since the station is last connected
			info.Connected = time.Duration(nlenc.Uint32(a.Data)) * time.Second
		case nl80211.StaInfoInactiveTime:
			// * @NL80211_STA_INFO_INACTIVE_TIME: time since last activity (u32, msecs)
			info.Inactive = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case nl80211.StaInfoRxBytes64:
			info.ReceivedBytes = int(nlenc.Uint64(a.Data))
		case nl80211.StaInfoTxBytes64:
			info.TransmittedBytes = int(nlenc.Uint64(a.Data))
		case nl80211.StaInfoSignal:
			//  * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
			// Should just be cast to int8, see code here: https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git/tree/station.c#n378
			info.Signal = int(int8(a.Data[0]))
		case nl80211.StaInfoRxPackets:
			info.ReceivedPackets = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoTxPackets:
			info.TransmittedPackets = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoTxRetries:
			info.TransmitRetries = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoTxFailed:
			info.TransmitFailed = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoBeaconLoss:
			info.BeaconLoss = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoRxBitrate, nl80211.StaInfoTxBitrate:
			rate, err := parseRateInfo(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more statistics if they end up being
			// generally useful
			switch a.Type {
			case nl80211.StaInfoRxBitrate:
				info.ReceiveBitrate = rate.Bitrate
			case nl80211.StaInfoTxBitrate:
				info.TransmitBitrate = rate.Bitrate
			}
		}

		// Only use 32-bit counters if the 64-bit counters are not present.
		// If the 64-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.ReceivedBytes == 0 && a.Type == nl80211.StaInfoRxBytes {
			info.ReceivedBytes = int(nlenc.Uint32(a.Data))
		}
		if info.TransmittedBytes == 0 && a.Type == nl80211.StaInfoTxBytes {
			info.TransmittedBytes = int(nlenc.Uint32(a.Data))
		}
	}

	return nil
}

// rateInfo provides statistics about the receive or transmit rate of
// an interface.
type rateInfo struct {
	// Bitrate in bits per second.
	Bitrate int
}

// parseRateInfo parses a rateInfo from netlink attributes.
func parseRateInfo(b []byte) (*rateInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info rateInfo
	for _, a := range attrs {
		switch a.Type {
		case nl80211.RateInfoBitrate32:
			info.Bitrate = int(nlenc.Uint32(a.Data))
		}

		// Only use 16-bit counters if the 32-bit counters are not present.
		// If the 32-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.Bitrate == 0 && a.Type == nl80211.RateInfoBitrate {
			info.Bitrate = int(nlenc.Uint16(a.Data))
		}
	}

	// Scale bitrate to bits/second as base unit instead of 100kbits/second.
	// * @NL80211_RATE_INFO_BITRATE: total bitrate (u16, 100kbit/s)
	info.Bitrate *= 100 * 1000

	return &info, nil
}

// attrsContain checks if a slice of netlink attributes contains an attribute
// with the specified type.
func attrsContain(attrs []netlink.Attribute, typ uint16) bool {
	for _, a := range attrs {
		if a.Type == typ {
			return true
		}
	}

	return false
}

// decodeSSID safely parses a byte slice into UTF-8 runes, and returns the
// resulting string from the runes.
func decodeSSID(b []byte) string {
	buf := bytes.NewBuffer(nil)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]

		buf.WriteRune(r)
	}

	return buf.String()
}
