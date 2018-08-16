//+build linux

package wifi

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
	"unicode/utf8"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/wifi/internal/nl80211"
)

// Errors which may occur when interacting with generic netlink.
var (
	errInvalidCommand       = errors.New("invalid generic netlink response command")
	errInvalidFamilyVersion = errors.New("invalid generic netlink response family version")
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

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewInterface); err != nil {
		return nil, err
	}

	return parseInterfaces(msgs)
}

// PHY requests that nl80211 return information for the physical device
// specified by the index.
func (c *client) PHY(n int) (*PHY, error) {
	attrs := []netlink.Attribute{
		{
			Type: nl80211.AttrWiphy,
			Data: nlenc.Uint32Bytes(uint32(n)),
		},
	}
	phys, err := c.getPHYs(attrs)
	if err != nil {
		return nil, err
	}
	if len(phys) == 0 {
		return nil, fmt.Errorf("No PHY with index %d", n)
	}
	return phys[0], nil
}

// PHYs requests that nl80211 return information for all wireless physical
// devices.
func (c *client) PHYs() ([]*PHY, error) {
	attrs := make([]netlink.Attribute, 0)
	return c.getPHYs(attrs)
}

// getPHYs is the back-end for PHY() and PHYs(): building and making the netlink
// call, and parsing the response.
func (c *client) getPHYs(attrs []netlink.Attribute) ([]*PHY, error) {
	// The kernel, as of 3713b4e364eff (3.10), doesn't emit all information
	// unless SplitWiphyDump is set.  We could check for it by issuing
	// CmdGetProtocolFeatures and seeing if ProtocolFeatureSplitWiphyDump is
	// set, if we care about kernels that old ...
	attrs = append(attrs, netlink.Attribute{Type: nl80211.AttrSplitWiphyDump})
	nlattrs, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetWiphy,
			Version: c.familyVersion,
		},
		Data: nlattrs,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewWiphy); err != nil {
		return nil, err
	}

	return parsePHYs(msgs)
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

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewScanResults); err != nil {
		return nil, err
	}

	return parseBSS(msgs)
}

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

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
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

func parsePHYs(msgs []genetlink.Message) ([]*PHY, error) {
	phys := make([]*PHY, 0)
	var phy *PHY
	curphynum := -1
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		// Because we get a single stream of messages spanning multiple
		// PHYs, we have to peek into the attributes to see if it's the
		// same PHY as we've been processing.
		phynum, err := phyNumber(attrs)
		if err != nil {
			return nil, err
		}
		if phynum != curphynum {
			phy = new(PHY)
			phy.Extra = make(map[uint16][]byte, 0)
			phys = append(phys, phy)
			curphynum = phynum
		}

		if err := phy.parseAttributes(attrs); err != nil {
			return nil, err
		}
	}
	return phys, nil
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

// phyNumber extracts the first integer device index (AttrWiphy) from a list of
// netlink attributes.
func phyNumber(attrs []netlink.Attribute) (int, error) {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.AttrWiphy:
			return int(nlenc.Uint32(a.Data)), nil
		}
	}
	return 0, fmt.Errorf("there was no wiphy attribute")
}

// parseAttributes parses netlink attributes into a PHY's fields.
func (p *PHY) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.AttrWiphy:
			p.Index = int(nlenc.Uint32(a.Data))

		case nl80211.AttrWiphyName:
			p.Name = nlenc.String(a.Data)

		case nl80211.AttrSupportedIftypes:
			// This contains nested attributes with no data; the
			// data we care about is the type.
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for _, na := range nattrs {
				p.SupportedIftypes = append(p.SupportedIftypes, InterfaceType(na.Type))
			}

		case nl80211.AttrSoftwareIftypes:
			// This contains nested attributes with no data; the
			// data we care about is the type.
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for _, na := range nattrs {
				p.SoftwareIftypes = append(p.SoftwareIftypes, InterfaceType(na.Type))
			}

		case nl80211.AttrWiphyBands:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for i, band := range nattrs {
				// band.Type has the band number
				err := p.parseBandAttributes(band)
				if err != nil {
					return fmt.Errorf("Couldn't decode band %d (attr#%d) data: %s",
						band.Type, i, err)
				}
			}

		case nl80211.AttrInterfaceCombinations:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for i, combo := range nattrs {
				c, err := parseCombo(combo)
				if err != nil {
					return fmt.Errorf("Couldn't decode combo %d data: %s", i, err)
				}
				p.InterfaceCombinations = append(p.InterfaceCombinations, *c)
			}

		default:
			p.Extra[a.Type] = a.Data
		}
	}
	return nil
}

// parseCombo parses a netlink attribute into an InterfaceCombination.
func parseCombo(comboNLA netlink.Attribute) (*InterfaceCombination, error) {
	attrs, err := netlink.UnmarshalAttributes(comboNLA.Data)
	if err != nil {
		return nil, err
	}

	combo := &InterfaceCombination{}
	for _, attr := range attrs {
		switch attr.Type {
		case nl80211.IfaceCombLimits:
			lattrs, err := netlink.UnmarshalAttributes(attr.Data)
			if err != nil {
				return nil, err
			}

			for _, l := range lattrs {
				comboLimit := InterfaceCombinationLimit{}
				ltypes, err := netlink.UnmarshalAttributes(l.Data)
				if err != nil {
					return nil, err
				}

				for _, la := range ltypes {
					switch la.Type {
					case nl80211.IfaceLimitMax:
						comboLimit.Max = int(nlenc.Uint32(la.Data))
					case nl80211.IfaceLimitTypes:
						types, err := netlink.UnmarshalAttributes(la.Data)
						if err != nil {
							return nil, err
						}

						for _, typ := range types {
							comboLimit.InterfaceTypes = append(comboLimit.InterfaceTypes, InterfaceType(typ.Type))
						}
					}
				}
				combo.CombinationLimits = append(combo.CombinationLimits, comboLimit)
			}

		case nl80211.IfaceCombNumChannels:
			combo.NumChannels = int(nlenc.Uint32(attr.Data))

		case nl80211.IfaceCombMaxnum:
			combo.Total = int(nlenc.Uint32(attr.Data))

		case nl80211.IfaceCombStaApBiMatch:
			combo.StaApBiMatch = true
		}
	}
	return combo, nil
}

// parseBandAttributes parses a netlink attribute into the band-specific data of
// a PHY.
func (p *PHY) parseBandAttributes(nlband netlink.Attribute) error {
	attrs, err := netlink.UnmarshalAttributes(nlband.Data)
	if err != nil {
		return err
	}

	// We'll get called multiple times for individual attributes of a band,
	// so be sure to use the right element of the BandAttributes array, or
	// add new ones if we haven't seen the band before.  The expectation is
	// that we'll get them in order, 0..n, but this should work for any
	// ordering.
	for int(nlband.Type)+1 > len(p.BandAttributes) {
		ba := &BandAttributes{}
		p.BandAttributes = append(p.BandAttributes, *ba)
	}
	ba := &p.BandAttributes[nlband.Type]

	for _, attr := range attrs {
		switch attr.Type {
		case nl80211.BandAttrHtCapa:
			ba.HTCapabilities = decodeHTCapabilities(ba.HTCapabilities, nlenc.Uint16(attr.Data))

		case nl80211.BandAttrHtAmpduFactor:
			exponent := nlenc.Uint8(attr.Data)
			// The exponent comes from three bits of OTA data, but
			// netlink gives it to us as an 8-bit value.
			if exponent < 4 {
				// If we haven't seen BandAttrHtCapa yet, we
				// need to create the struct first.
				if ba.HTCapabilities == nil {
					ba.HTCapabilities = new(HTCapabilities)
				}
				ba.HTCapabilities.MaxRxAMPDULength = (1 << (13 + exponent)) - 1
			}

		case nl80211.BandAttrHtAmpduDensity:
			spacing := nlenc.Uint8(attr.Data)
			if spacing > 0 {
				ba.MinRxAMPDUSpacing = (1 << (spacing - 1)) * time.Microsecond / 4
			}

		case nl80211.BandAttrHtMcsSet:
		case nl80211.BandAttrVhtCapa:
		case nl80211.BandAttrVhtMcsSet:
			// TODO Handle these

		case nl80211.BandAttrRates:
			nattrs, err := netlink.UnmarshalAttributes(attr.Data)
			if err != nil {
				return err
			}
			// It doesn't look like we need to take as much care to
			// build up the BitrateAttributes array as we do the
			// FrequenceAttributes array, since it appears we get
			// all of the former back in a single message.  But just
			// in case ...
			for _, nlbra := range nattrs {
				brattrs, err := netlink.UnmarshalAttributes(nlbra.Data)
				if err != nil {
					return err
				}
				var bra BitrateAttrs
				for _, bra2 := range brattrs {
					switch bra2.Type {
					case nl80211.BitrateAttrRate:
						bra.Bitrate = 0.1 * float32(nlenc.Uint32(bra2.Data))
					case nl80211.BitrateAttr2ghzShortpreamble:
						bra.ShortPreamble = true
					}
				}
				ba.BitrateAttributes = append(ba.BitrateAttributes, bra)
			}

		case nl80211.BandAttrFreqs:
			nattrs, err := netlink.UnmarshalAttributes(attr.Data)
			if err != nil {
				return err
			}
			for _, nlfa := range nattrs {
				fattrs, err := netlink.UnmarshalAttributes(nlfa.Data)
				if err != nil {
					return err
				}
				var fa FrequencyAttrs
				for _, fa2 := range fattrs {
					switch fa2.Type {
					case nl80211.FrequencyAttrFreq:
						fa.Frequency = int(nlenc.Uint32(fa2.Data))
					case nl80211.FrequencyAttrDisabled:
						fa.Disabled = true
					// In 8fe02e167efa8 (3.14), Linux renamed the
					// PASSIVE_SCAN frequency attribute to NO_IR,
					// and deprecated NO_IBSS (4).  It sends both,
					// but we don't need to support old kernels.
					case nl80211.FrequencyAttrNoIr:
						fa.NoIR = true
					case nl80211.FrequencyAttrRadar:
						fa.RadarDetection = true
					case nl80211.FrequencyAttrMaxTxPower:
						fa.MaxTxPower = 0.01 * float32(nlenc.Uint32(fa2.Data))
					}
				}
				ba.FrequencyAttributes = append(ba.FrequencyAttributes, fa)
			}
		}
	}

	return nil
}

// decodeHTCapabilities parses a 16-bit integer into an HTCapabilities struct
// based on information from an HT Capabilities Info field (BandAttrHtCapa).
// Create a new one if nil is passed in, but allow for the struct to have other
// fields already set.
func decodeHTCapabilities(htcap *HTCapabilities, cap uint16) *HTCapabilities {
	if htcap == nil {
		htcap = new(HTCapabilities)
	}

	htcap.RxLDPC = cap&(1<<0) != 0
	htcap.HT2040 = cap&(1<<1) != 0
	htcap.RxGreenfield = cap&(1<<4) != 0
	htcap.RxHT20SGI = cap&(1<<5) != 0
	htcap.RxHT40SGI = cap&(1<<6) != 0
	htcap.TxSTBC = cap&(1<<7) != 0
	htcap.RxSTBCStreams = uint8((cap >> 8) & 0x3)
	htcap.HTDelayedBlockAck = cap&(1<<10) != 0
	htcap.LongMaxAMSDULength = cap&(1<<11) != 0
	htcap.DSSSCCKHT40 = cap&(1<<12) != 0
	htcap.FortyMhzIntolerant = cap&(1<<14) != 0
	htcap.LSIGTxOPProtection = cap&(1<<15) != 0

	return htcap
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
