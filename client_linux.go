//go:build linux

package wifi

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/unix"
)

var (
	ErrNotSupported      = errors.New("not supported")
	ErrScanGroupNotFound = errors.New("scan multicast group unavailable")
	ErrScanAborted       = errors.New("scan aborted by the kernel")
	ErrScanValidation    = errors.New("scan validation failed")
)

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type client struct {
	c             *genetlink.Conn
	familyID      uint16
	familyVersion uint8

	// scan is used to synchronize access to the Scan method.
	scan sync.Mutex
}

// newClient dials a generic netlink connection and verifies that nl80211
// is available for use by this package.
func newClient() (*client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	// Make a best effort to apply the strict options set to provide better
	// errors and validation. We don't apply Strict in the constructor because
	// this library is widely used on a range of kernels and we can't guarantee
	// it will always work on older kernels.
	for _, o := range []netlink.ConnOption{
		netlink.ExtendedAcknowledge,
		netlink.GetStrictCheck,
	} {
		_ = c.SetOption(o, true)
	}

	return initClient(c)
}

func initClient(c *genetlink.Conn) (*client, error) {
	family, err := c.GetFamily(unix.NL80211_GENL_NAME)
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

		scan: sync.Mutex{},
	}, nil
}

// Close closes the client's generic netlink connection.
func (c *client) Close() error { return c.c.Close() }

// Interfaces requests that nl80211 return a list of all WiFi interfaces present
// on this system.
func (c *client) Interfaces() ([]*Interface, error) {
	// Ask nl80211 to dump a list of all WiFi interfaces
	msgs, err := c.get(
		unix.NL80211_CMD_GET_INTERFACE,
		netlink.Dump,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return ParseInterfaces(msgs)
}

// PHY requests that nl80211 return information for the physical device
// specified by the index.
func (c *client) PHY(n uint32) (*PHY, error) {
	phys, err := c.getPHYs(&n)
	if err != nil {
		return nil, err
	}
	if len(phys) == 0 {
		return nil, fmt.Errorf("no PHY with index %d", n)
	}
	return phys[0], nil
}

// PHYs requests that nl80211 return information for all wireless physical
// devices.
func (c *client) PHYs() ([]*PHY, error) {
	return c.getPHYs(nil)
}

// getPHYs is the back-end for PHY() and PHYs(): building and making the netlink
// call, and parsing the response.
func (c *client) getPHYs(n *uint32) ([]*PHY, error) {
	// The kernel, as of 3713b4e364eff (3.10), doesn't emit all information
	// unless SplitWiphyDump is set.  We could check for it by issuing
	// CmdGetProtocolFeatures and seeing if ProtocolFeatureSplitWiphyDump is
	// set, if we care about kernels that old ...
	msgs, err := c.get(unix.NL80211_CMD_GET_WIPHY, netlink.Dump, nil, func(ae *netlink.AttributeEncoder) {
		ae.Flag(unix.NL80211_ATTR_SPLIT_WIPHY_DUMP, true)
		if n != nil {
			ae.Uint32(unix.NL80211_ATTR_WIPHY, *n)
		}
	})
	if err != nil {
		return nil, err
	}
	return parsePHYs(msgs)
}

// Connect starts connecting the interface to the specified ssid.
func (c *client) Connect(ifi *Interface, ssid string) error {
	// Ask nl80211 to connect to the specified SSID.
	_, err := c.get(
		unix.NL80211_CMD_CONNECT,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)
		},
	)
	return err
}

// Disconnect disconnects the interface.
func (c *client) Disconnect(ifi *Interface) error {
	// Ask nl80211 to disconnect.
	_, err := c.get(
		unix.NL80211_CMD_DISCONNECT,
		netlink.Acknowledge,
		ifi,
		nil,
	)
	return err
}

// ConnectWPAPSK starts connecting the interface to the specified SSID using
// WPA.
func (c *client) ConnectWPAPSK(ifi *Interface, ssid, psk string) error {
	support, err := c.checkExtFeature(ifi, unix.NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK)
	if err != nil {
		return err
	}
	if !support {
		return ErrNotSupported
	}

	// Ask nl80211 to connect to the specified SSID with key..
	_, err = c.get(
		unix.NL80211_CMD_CONNECT,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// TODO(mdlayher): document these or build from bitflags.
			const (
				cipherSuites = 0xfac04
				akmSuites    = 0xfac02
			)

			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_WPA_VERSIONS, unix.NL80211_WPA_VERSION_2)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITE_GROUP, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITES_PAIRWISE, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_AKM_SUITES, akmSuites)
			ae.Flag(unix.NL80211_ATTR_WANT_1X_4WAY_HS, true)
			ae.Bytes(
				unix.NL80211_ATTR_PMK,
				wpaPassphrase([]byte(ssid), []byte(psk)),
			)
			ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)
		},
	)
	return err
}

// wpaPassphrase computes a WPA passphrase given an SSID and preshared key.
func wpaPassphrase(ssid, psk []byte) []byte {
	return pbkdf2.Key(psk, ssid, 4096, 32, sha1.New)
}

// BSS requests that nl80211 return the BSS for the specified Interface.
func (c *client) BSS(ifi *Interface) (*BSS, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_SCAN,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			if ifi.HardwareAddr != nil {
				ae.Bytes(unix.NL80211_ATTR_MAC, ifi.HardwareAddr)
			}
		},
	)
	if err != nil {
		return nil, err
	}

	return parseBSS(msgs)
}

// AccessPoints requests that nl80211 return all currently known BSS
// from the specified Interface.
func (c *client) AccessPoints(ifi *Interface) ([]*BSS, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_SCAN,
		netlink.Dump,
		ifi,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return parseGetScanResult(msgs)
}

// StationInfo requests that nl80211 return all station info for the specified
// Interface.
func (c *client) StationInfo(ifi *Interface) ([]*StationInfo, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_STATION,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			if ifi.HardwareAddr != nil {
				ae.Bytes(unix.NL80211_ATTR_MAC, ifi.HardwareAddr)
			}
		},
	)
	if err != nil {
		return nil, err
	}

	stations := make([]*StationInfo, len(msgs))
	for i := range msgs {
		if stations[i], err = ParseStationInfo(msgs[i].Data); err != nil {
			return nil, err
		}
	}

	return stations, nil
}

// SurveyInfo requests that nl80211 return a list of survey information for the
// specified Interface.
func (c *client) SurveyInfo(ifi *Interface) ([]*SurveyInfo, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_SURVEY,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			if ifi.HardwareAddr != nil {
				ae.Bytes(unix.NL80211_ATTR_MAC, ifi.HardwareAddr)
			}
		},
	)
	if err != nil {
		return nil, err
	}

	surveys := make([]*SurveyInfo, len(msgs))
	for i := range msgs {
		if surveys[i], err = parseSurveyInfo(msgs[i].Data); err != nil {
			return nil, err
		}
	}
	return surveys, nil
}

// Scan requests that nl80211 perform a scan for new access points using
// the specified Interface. This process is long running and uses
// a separate connection to nl80211.
//
// Use context.WithDeadline to set a timeout.
//
// If a scan is already in progress, this function will return a syscall.EBUSY
// error. If the response cannot be validated, the returned error
// will include ErrScanValidation.
//
// Use func AccessPoints to retrieve the results.
func (c *client) Scan(ctx context.Context, ifi *Interface) error {
	c.scan.Lock()
	defer c.scan.Unlock()

	// use secondary connection for multicast receives
	conn, err := genetlink.Dial(&netlink.Config{Strict: true})
	if err != nil {
		return err
	}

	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		err := conn.SetDeadline(deadline)
		if err != nil {
			return err
		}
	}

	family, err := conn.GetFamily(unix.NL80211_GENL_NAME)
	if err != nil {
		return err
	}

	var id uint32
	for _, group := range family.Groups {
		if group.Name == unix.NL80211_MULTICAST_GROUP_SCAN {
			err = conn.JoinGroup(group.ID)
			if err != nil {
				return err
			}

			id = group.ID
			break
		}
	}

	if id == 0 {
		return ErrScanGroupNotFound
	}

	// Leave group on exit. Err is non-actionable
	defer func() { _ = conn.LeaveGroup(id) }()

	enc := netlink.NewAttributeEncoder()
	enc.Nested(unix.NL80211_ATTR_SCAN_SSIDS, func(ae *netlink.AttributeEncoder) error {
		ae.Bytes(unix.NL80211_SCHED_SCAN_MATCH_ATTR_SSID, nlenc.Bytes(""))
		return nil
	})

	ifi.encode(enc)

	data, err := enc.Encode()
	if err != nil {
		return err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: unix.NL80211_CMD_TRIGGER_SCAN,
			Version: c.familyVersion,
		},
		Data: data,
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	result := make(chan error, 1)
	go func(ctx context.Context, conn *genetlink.Conn, ifiIndex int, familyVersion uint8, result chan<- error) {

		defer close(result)
		result <- listenNewScanResults(ctx, conn, ifiIndex, familyVersion)

	}(ctx, conn, ifi.Index, c.familyVersion, result)

	flags := netlink.Request | netlink.Acknowledge

	_, err = conn.Send(req, family.ID, flags)
	if err != nil {
		cancel()
	}

	err2 := <-result

	return errors.Join(err, err2)
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (c *client) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

// SetReadDeadline sets the read deadline associated with the connection.
func (c *client) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline associated with the connection.
func (c *client) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

// get performs a request/response interaction with nl80211.
func (c *client) get(
	cmd uint8,
	flags netlink.HeaderFlags,
	ifi *Interface,
	// May be nil; used to apply optional parameters.
	params func(ae *netlink.AttributeEncoder),
) ([]genetlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	ifi.encode(ae)
	if params != nil {
		// Optionally apply more parameters to the attribute encoder.
		params(ae)
	}

	// Note: don't send netlink.Acknowledge or we get an extra message back from
	// the kernel which doesn't seem useful as of now.
	return c.execute(cmd, flags, ae)
}

// execute executes the specified command with additional header flags and input
// netlink request attributes. The netlink.Request header flag is automatically
// set.
func (c *client) execute(
	cmd uint8,
	flags netlink.HeaderFlags,
	ae *netlink.AttributeEncoder,
) ([]genetlink.Message, error) {
	b, err := ae.Encode()
	if err != nil {
		return nil, err
	}

	return c.c.Execute(
		genetlink.Message{
			Header: genetlink.Header{
				Command: cmd,
				Version: c.familyVersion,
			},
			Data: b,
		},
		// Always pass the genetlink family ID and request flag.
		c.familyID,
		netlink.Request|flags,
	)
}

// listenNewScanResults listens for new scan results or scan abort messages
// from the netlink connection. It processes the messages associated with the
// specified interface index and family version, verifying attributes and
// handling context cancellations.
//
// The caller should not receive on the given connection and is responsible
// for closing it.
func listenNewScanResults(ctx context.Context, conn *genetlink.Conn, ifiIndex int, familyVersion uint8) error {
	for ctx.Err() == nil {
		msgs, _, err := conn.Receive()
		if err != nil {
			return err
		}

		// test for context cancellation and abandon work if so
		if ctx.Err() != nil {
			return err
		}

		for _, msg := range msgs {
			if msg.Header.Version != familyVersion {
				break
			}

			switch msg.Header.Command {
			case unix.NL80211_CMD_SCAN_ABORTED:
				return ErrScanAborted
			case unix.NL80211_CMD_NEW_SCAN_RESULTS:
				// attempt to verify the interface
				attrs, err := netlink.UnmarshalAttributes(msg.Data)
				if err != nil {
					return errors.Join(ErrScanValidation, err)
				}

				var intf Interface
				if err := (&intf).parseAttributes(attrs); err != nil {
					return errors.Join(ErrScanValidation, err)
				}

				if ifiIndex != intf.Index {
					continue
				}

				return nil
			default:
				continue
			}

		}
	}

	return ctx.Err()
}

// parseGetScanResult parses all the BSS from nl80211 CMD_GET_SCAN response messages.
func parseGetScanResult(msgs []genetlink.Message) ([]*BSS, error) {
	// reimplementing https://github.com/mdlayher/wifi/pull/79
	bsss := make([]*BSS, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var bss BSS
		for _, a := range attrs {
			if a.Type != unix.NL80211_ATTR_BSS {
				continue
			}

			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if !attrsContain(nattrs, unix.NL80211_BSS_STATUS) {
				bss.Status = BSSStatusNotAssociated
			}

			if err := (&bss).parseAttributes(nattrs); err != nil {
				continue
			}
		}
		bsss = append(bsss, &bss)
	}
	return bsss, nil
}

// parseInterfaces parses zero or more Interfaces from nl80211 interface
// messages.
func ParseInterfaces(msgs []genetlink.Message) ([]*Interface, error) {
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

// encode provides an encoding function for ifi's attributes. If ifi is nil,
// encode is a no-op.
func (ifi *Interface) encode(ae *netlink.AttributeEncoder) {
	if ifi == nil {
		return
	}

	// Mandatory.
	ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
}

// idAttrs returns the netlink attributes required from an Interface to retrieve
// more data about it.
func (ifi *Interface) idAttrs() []netlink.Attribute {
	return []netlink.Attribute{
		{
			Type: unix.NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
		{
			Type: unix.NL80211_ATTR_MAC,
			Data: ifi.HardwareAddr,
		},
	}
}

// parseAttributes parses netlink attributes into an Interface's fields.
func (ifi *Interface) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_IFINDEX:
			ifi.Index = int(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_IFNAME:
			ifi.Name = nlenc.String(a.Data)
		case unix.NL80211_ATTR_MAC:
			ifi.HardwareAddr = net.HardwareAddr(a.Data)
		case unix.NL80211_ATTR_WIPHY:
			ifi.PHY = int(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_IFTYPE:
			// NOTE: InterfaceType copies the ordering of nl80211's interface type
			// constants.  This may not be the case on other operating systems.
			ifi.Type = InterfaceType(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_WDEV:
			ifi.Device = int(nlenc.Uint64(a.Data))
		case unix.NL80211_ATTR_WIPHY_FREQ:
			ifi.Frequency = int(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_CHANNEL_WIDTH:
			ifi.ChannelWidth = ChannelWidth(nlenc.Uint32(a.Data))
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
			if a.Type != unix.NL80211_ATTR_BSS {
				continue
			}

			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			// The BSS which is associated with an interface will have a status
			// attribute
			if !attrsContain(nattrs, unix.NL80211_BSS_STATUS) {
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

// phyNumber extracts the first integer device index (AttrWiphy) from a list of
// netlink attributes.
func phyNumber(attrs []netlink.Attribute) (int, error) {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_WIPHY:
			return int(nlenc.Uint32(a.Data)), nil
		}
	}
	return 0, fmt.Errorf("there was no wiphy attribute")
}

// parseAttributes parses netlink attributes into a PHY's fields.
func (p *PHY) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_WIPHY:
			p.Index = int(nlenc.Uint32(a.Data))

		case unix.NL80211_ATTR_WIPHY_NAME:
			p.Name = nlenc.String(a.Data)

		case unix.NL80211_ATTR_SUPPORTED_IFTYPES:
			// This contains nested attributes with no data; the
			// data we care about is the type.
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for _, na := range nattrs {
				p.SupportedIftypes = append(p.SupportedIftypes, InterfaceType(na.Type))
			}

		case unix.NL80211_ATTR_SOFTWARE_IFTYPES:
			// This contains nested attributes with no data; the
			// data we care about is the type.
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for _, na := range nattrs {
				p.SoftwareIftypes = append(p.SoftwareIftypes, InterfaceType(na.Type))
			}

		case unix.NL80211_ATTR_WIPHY_BANDS:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for i, band := range nattrs {
				// band.Type has the band number
				err := p.parseBandAttributes(band)
				if err != nil {
					return fmt.Errorf("could not decode band %d (attr#%d) data: %s",
						band.Type, i, err)
				}
			}

		case unix.NL80211_ATTR_INTERFACE_COMBINATIONS:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return err
			}
			for i, combo := range nattrs {
				c, err := parseCombo(combo)
				if err != nil {
					return fmt.Errorf("could not decode combo %d data: %s", i, err)
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
		case unix.NL80211_IFACE_COMB_LIMITS:
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
					case unix.NL80211_IFACE_LIMIT_MAX:
						comboLimit.Max = int(nlenc.Uint32(la.Data))
					case unix.NL80211_IFACE_LIMIT_TYPES:
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

		case unix.NL80211_IFACE_COMB_NUM_CHANNELS:
			combo.NumChannels = int(nlenc.Uint32(attr.Data))

		case unix.NL80211_IFACE_COMB_MAXNUM:
			combo.Total = int(nlenc.Uint32(attr.Data))

		case unix.NL80211_IFACE_COMB_STA_AP_BI_MATCH:
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
		case unix.NL80211_BAND_ATTR_HT_CAPA:
			ba.HTCapabilities = decodeHTCapabilities(ba.HTCapabilities, nlenc.Uint16(attr.Data))

		case unix.NL80211_BAND_ATTR_HT_AMPDU_FACTOR:
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

		case unix.NL80211_BAND_ATTR_HT_AMPDU_DENSITY:
			spacing := nlenc.Uint8(attr.Data)
			if spacing > 0 {
				ba.MinRxAMPDUSpacing = (1 << (spacing - 1)) * time.Microsecond / 4
			}

		case unix.NL80211_BAND_ATTR_VHT_CAPA:
			ba.VHTCapabilities = decodeVHTCapabilities(ba.VHTCapabilities, nlenc.Uint32(attr.Data))
		case unix.NL80211_BAND_ATTR_HT_MCS_SET:
			if ba.HTCapabilities == nil {
				ba.HTCapabilities = new(HTCapabilities)
			}
			copy(ba.HTCapabilities.SupportedMCS[:], attr.Data)
		case unix.NL80211_BAND_ATTR_VHT_MCS_SET:
			if ba.VHTCapabilities == nil {
				ba.VHTCapabilities = new(VHTCapabilities)
			}
			copy(ba.VHTCapabilities.SupportedMCS[:], attr.Data)

		case unix.NL80211_BAND_ATTR_RATES:
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
					case unix.NL80211_BITRATE_ATTR_RATE:
						bra.Bitrate = 0.1 * float32(nlenc.Uint32(bra2.Data))
					case unix.NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE:
						bra.ShortPreamble = true
					}
				}
				ba.BitrateAttributes = append(ba.BitrateAttributes, bra)
			}

		case unix.NL80211_BAND_ATTR_FREQS:
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
					case unix.NL80211_FREQUENCY_ATTR_FREQ:
						fa.Frequency = int(nlenc.Uint32(fa2.Data))
					case unix.NL80211_FREQUENCY_ATTR_DISABLED:
						fa.Disabled = true
					// In 8fe02e167efa8 (3.14), Linux renamed the
					// PASSIVE_SCAN frequency attribute to NO_IR,
					// and deprecated NO_IBSS (4).  It sends both,
					// but we don't need to support old kernels.
					case unix.NL80211_FREQUENCY_ATTR_NO_IR:
						fa.NoIR = true
					case unix.NL80211_FREQUENCY_ATTR_RADAR:
						fa.RadarDetection = true
					case unix.NL80211_FREQUENCY_ATTR_MAX_TX_POWER:
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
// based on information from an HT Capabilities Info field (NL80211_BAND_ATTR_HT_CAPA).
// Create a new one if nil is passed in, but allow for the struct to have other
// fields already set.
func decodeHTCapabilities(htcap *HTCapabilities, capability uint16) *HTCapabilities {
	if htcap == nil {
		htcap = new(HTCapabilities)
	}

	htcap.RxLDPC = capability&(1<<0) != 0
	htcap.CW40 = capability&(1<<1) != 0
	htcap.HTGreenfield = capability&(1<<4) != 0
	htcap.SGI20 = capability&(1<<5) != 0
	htcap.SGI40 = capability&(1<<6) != 0
	htcap.TxSTBC = capability&(1<<7) != 0
	htcap.RxSTBCStreams = uint8((capability >> 8) & 0x3)
	htcap.HTDelayedBlockAck = capability&(1<<10) != 0
	htcap.LongMaxAMSDULength = capability&(1<<11) != 0
	htcap.DSSSCCKHT40 = capability&(1<<12) != 0
	htcap.FortyMhzIntolerant = capability&(1<<14) != 0
	htcap.LSIGTxOPProtection = capability&(1<<15) != 0

	return htcap
}

// decodeVHTCapabilities parses a 32-bit integer into an VHTCapabilities struct
// based on information from an VHT Capabilities Info field (NL80211_BAND_ATTR_VHT_CAPA).
// Create a new one if nil is passed in, but allow for the struct to have other
// fields already set.
func decodeVHTCapabilities(vhtcap *VHTCapabilities, capability uint32) *VHTCapabilities {
	if vhtcap == nil {
		vhtcap = new(VHTCapabilities)
	}
	switch int(capability & 0x3) {
	case 0:
		vhtcap.MaxMPDULength = 3895
	case 1:
		vhtcap.MaxMPDULength = 7991
	case 2:
		vhtcap.MaxMPDULength = 11454
	}
	vhtcap.VHT160 = capability&(1<<2) != 0
	vhtcap.VHT8080 = capability&(1<<3) != 0
	vhtcap.RXLDPC = capability&(1<<4) != 0
	vhtcap.ShortGI80 = capability&(1<<5) != 0
	vhtcap.ShortGI160 = capability&(1<<6) != 0
	vhtcap.TXSTBC = capability&(1<<7) != 0
	vhtcap.RXSTBC = int((capability >> 8) & 0x7)
	vhtcap.SuBeamFormer = capability&(1<<11) != 0
	vhtcap.SuBeamFormee = capability&(1<<12) != 0
	vhtcap.BFAntenna = int((capability>>13)&0x7) - 1
	vhtcap.SoundingDimension = int((capability >> 16) & 0x7)
	vhtcap.MuBeamformer = capability&(1<<19) != 0
	vhtcap.MuBeamformee = capability&(1<<20) != 0
	vhtcap.VTHTXOPPS = capability&(1<<21) != 0
	vhtcap.HTCVHT = capability&(1<<22) != 0
	vhtcap.MaxAMPDU = 2 ^ (13 + int((capability>>23)&0x2)) - 1
	vhtcap.VHTLinkAdapt = int((capability >> 27) & 0x3)
	vhtcap.RXAntennaPattern = capability&(1<<28) != 0
	vhtcap.TXAntennaPattern = capability&(1<<29) != 0
	vhtcap.ExtendedNSSBW = int((capability >> 30) & 0x7)

	return vhtcap
}

// parseAttributes parses netlink attributes into a BSS's fields.
func (b *BSS) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_BSS_BSSID:
			b.BSSID = net.HardwareAddr(a.Data)
		case unix.NL80211_BSS_FREQUENCY:
			b.Frequency = int(nlenc.Uint32(a.Data))
		case unix.NL80211_BSS_BEACON_INTERVAL:
			// Raw value is in "Time Units (TU)".  See:
			// https://en.wikipedia.org/wiki/Beacon_frame
			b.BeaconInterval = time.Duration(nlenc.Uint16(a.Data)) * 1024 * time.Microsecond
		case unix.NL80211_BSS_SEEN_MS_AGO:
			// * @NL80211_BSS_SEEN_MS_AGO: age of this BSS entry in ms
			b.LastSeen = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case unix.NL80211_BSS_STATUS:
			// NOTE: BSSStatus copies the ordering of nl80211's BSS status
			// constants.  This may not be the case on other operating systems.
			b.Status = BSSStatus(nlenc.Uint32(a.Data))
		case unix.NL80211_BSS_SIGNAL_MBM:
			// * @NL80211_BSS_SIGNAL_MBM: signal strength in mBm (100*dBm)
			b.Signal = nlenc.Int32(a.Data)
		case unix.NL80211_BSS_SIGNAL_UNSPEC:
			// * @NL80211_BSS_SIGNAL_UNSPEC: signal strength in unspecified units (usually percent)
			b.SignalUnspecified = nlenc.Uint32(a.Data)
		case unix.NL80211_BSS_INFORMATION_ELEMENTS:
			ies, err := parseIEs(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more IEs if they end up being generally useful
			for _, ie := range ies {
				switch ie.ID {
				case ieSSID:
					b.SSID = decodeSSID(ie.Data)
				case ieBSSLoad:
					Bssload, err := decodeBSSLoad(ie.Data)
					if err != nil {
						continue // This IE is malformed
					}
					b.Load = *Bssload
				case ieRSN:
					rsnInfo, err := decodeRSN(ie.Data)
					if err != nil {
						continue // This IE is malformed
					}
					b.RSN = *rsnInfo
				}
			}
		}
	}

	return nil
}

// ParseStationInfo parses StationInfo attributes from a byte slice of
// netlink attributes.
func ParseStationInfo(b []byte) (*StationInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info StationInfo
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_IFINDEX:
			info.InterfaceIndex = int(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_MAC:
			info.HardwareAddr = net.HardwareAddr(a.Data)
		case unix.NL80211_ATTR_STA_INFO:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if err := (&info).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			// Parsed the necessary data.
			return &info, nil
		}
	}

	// No station info found
	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a StationInfo's fields.
func (info *StationInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_STA_INFO_CONNECTED_TIME:
			// Though nl80211 does not specify, this value appears to be in seconds:
			// * @NL80211_STA_INFO_CONNECTED_TIME: time since the station is last connected
			info.Connected = time.Duration(nlenc.Uint32(a.Data)) * time.Second
		case unix.NL80211_STA_INFO_INACTIVE_TIME:
			// * @NL80211_STA_INFO_INACTIVE_TIME: time since last activity (u32, msecs)
			info.Inactive = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case unix.NL80211_STA_INFO_RX_BYTES64:
			info.ReceivedBytes = int(nlenc.Uint64(a.Data))
		case unix.NL80211_STA_INFO_TX_BYTES64:
			info.TransmittedBytes = int(nlenc.Uint64(a.Data))
		case unix.NL80211_STA_INFO_SIGNAL:
			//  * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
			// Should just be cast to int8, see code here: https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git/tree/station.c#n378
			info.Signal = int(int8(a.Data[0]))
		case unix.NL80211_STA_INFO_SIGNAL_AVG:
			info.SignalAverage = int(int8(a.Data[0]))
		case unix.NL80211_STA_INFO_RX_PACKETS:
			info.ReceivedPackets = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_PACKETS:
			info.TransmittedPackets = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_RETRIES:
			info.TransmitRetries = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_FAILED:
			info.TransmitFailed = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_BEACON_LOSS:
			info.BeaconLoss = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_RX_BITRATE, unix.NL80211_STA_INFO_TX_BITRATE:
			rate, err := parseRateInfo(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more statistics if they end up being
			// generally useful
			switch a.Type {
			case unix.NL80211_STA_INFO_RX_BITRATE:
				info.ReceiveBitrate = rate.Bitrate
			case unix.NL80211_STA_INFO_TX_BITRATE:
				info.TransmitBitrate = rate.Bitrate
			}
		}

		// Only use 32-bit counters if the 64-bit counters are not present.
		// If the 64-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.ReceivedBytes == 0 && a.Type == unix.NL80211_STA_INFO_RX_BYTES {
			info.ReceivedBytes = int(nlenc.Uint32(a.Data))
		}
		if info.TransmittedBytes == 0 && a.Type == unix.NL80211_STA_INFO_TX_BYTES {
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
		case unix.NL80211_RATE_INFO_BITRATE32:
			info.Bitrate = int(nlenc.Uint32(a.Data))
		}

		// Only use 16-bit counters if the 32-bit counters are not present.
		// If the 32-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.Bitrate == 0 && a.Type == unix.NL80211_RATE_INFO_BITRATE {
			info.Bitrate = int(nlenc.Uint16(a.Data))
		}
	}

	// Scale bitrate to bits/second as base unit instead of 100kbits/second.
	// * @NL80211_RATE_INFO_BITRATE: total bitrate (u16, 100kbit/s)
	info.Bitrate *= 100 * 1000

	return &info, nil
}

// parseSurveyInfo parses a single SurveyInfo from a byte slice of netlink
// attributes.
func parseSurveyInfo(b []byte) (*SurveyInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info SurveyInfo
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_IFINDEX:
			info.InterfaceIndex = int(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_SURVEY_INFO:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if err := (&info).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			// Parsed the necessary data.
			return &info, nil
		}
	}

	// No survey info found
	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a SurveyInfo's fields.
func (s *SurveyInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_SURVEY_INFO_FREQUENCY:
			s.Frequency = int(nlenc.Uint32(a.Data))
		case unix.NL80211_SURVEY_INFO_NOISE:
			s.Noise = int(int8(a.Data[0]))
		case unix.NL80211_SURVEY_INFO_IN_USE:
			s.InUse = true
		case unix.NL80211_SURVEY_INFO_TIME:
			s.ChannelTime = time.Duration(nlenc.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_BUSY:
			s.ChannelTimeBusy = time.Duration(nlenc.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_EXT_BUSY:
			s.ChannelTimeExtBusy = time.Duration(nlenc.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_BSS_RX:
			s.ChannelTimeBssRx = time.Duration(nlenc.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_RX:
			s.ChannelTimeRx = time.Duration(nlenc.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_TX:
			s.ChannelTimeTx = time.Duration(nlenc.Uint64(a.Data)) * time.Millisecond
		case unix.NL80211_SURVEY_INFO_TIME_SCAN:
			s.ChannelTimeScan = time.Duration(nlenc.Uint64(a.Data)) * time.Millisecond
		}
	}

	return nil
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

// decodeBSSLoad Decodes the BSSLoad IE. Supports Version 1 and Version 2
// values according to https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-ieee80211.c
// See also source code of iw (v5.19) scan.c Line 1634ff
// BSS Load ELement (with length 5) is defined by chapter 9.4.2.27 (page 1066) of the current IEEE 802.11-2020
func decodeBSSLoad(b []byte) (*BSSLoad, error) {
	var load BSSLoad
	if len(b) == 5 {
		// Wireshark calls this "802.11e CCA Version"
		// This is the version defined in IEEE 802.11 (Versions 2007, 2012, 2016 and 2020)
		load.Version = 2
		load.StationCount = binary.LittleEndian.Uint16(b[0:2])               // first 2 bytes
		load.ChannelUtilization = b[2]                                       // next 1 byte
		load.AvailableAdmissionCapacity = binary.LittleEndian.Uint16(b[3:5]) // last 2 bytes
	} else if len(b) == 4 {
		// Wireshark calls this "Cisco QBSS Version 1 - non CCA"
		load.Version = 1
		load.StationCount = binary.LittleEndian.Uint16(b[0:2]) // first 2 bytes
		load.ChannelUtilization = b[2]                         // next 1 byte
		load.AvailableAdmissionCapacity = uint16(b[3])         // next 1 byte
	} else {
		return nil, errInvalidBSSLoad
	}
	return &load, nil
}

// decodeRSN parses IEEE 802.11 Element ID 48 (RSN Information Element).
// (RSN = Robust Security Network)
//
// The RSN IE structure is defined in IEEE 802.11-2020 standard, section 9.4.2.24 (page 1051).
func decodeRSN(b []byte) (*RSNInfo, error) {
	// IEEE 802.11 Information Elements are limited to 255 octets total (ID + Length + Data)
	// Since we receive only the data portion, maximum size is 253 bytes (255 - 1 - 1)
	if len(b) > 253 {
		return &RSNInfo{}, errRSNDataTooLarge
	}

	if len(b) < 8 { // minimum: version(2) + group cipher(4) + pairwise count(2)
		return &RSNInfo{}, errRSNTooShort
	}

	var ri RSNInfo
	ri.Version = binary.LittleEndian.Uint16(b[:2])

	// Note: Most implementations use version 1, but be tolerant of future versions
	// that maintain backward compatibility. Only reject version 0 as invalid.
	if ri.Version == 0 {
		return &ri, errRSNInvalidVersion
	}

	// Group cipher suite (4 octets) - OUI is stored big-endian in the data
	groupCipherOUI := binary.BigEndian.Uint32(b[2:6])
	ri.GroupCipher = RSNCipher(groupCipherOUI)
	pos := 6

	// Pairwise cipher list
	if len(b) < pos+2 {
		return &ri, errRSNTruncatedPairwiseCount
	}
	pcCount := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
	pos += 2

	if pcCount > 60 { // (253-10)/4 ≈ 60 (theoretical max with minimal overhead)
		return &ri, errRSNPairwiseCipherCountTooLarge
	}

	if len(b) < pos+4*pcCount {
		return &ri, errRSNTruncatedPairwiseList
	}

	ri.PairwiseCiphers = make([]RSNCipher, 0, pcCount) // Pre-allocate with known capacity
	for range pcCount {
		sel := binary.BigEndian.Uint32(b[pos : pos+4])
		ri.PairwiseCiphers = append(ri.PairwiseCiphers, RSNCipher(sel))
		pos += 4
	}

	// AKM list
	if len(b) < pos+2 {
		return &ri, nil // AKM list is optional, return what we have
	}
	akmCount := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
	pos += 2

	if akmCount > 60 { // (253-10)/4 ≈ 60 (theoretical max with minimal overhead)
		return &ri, errRSNAKMCountTooLarge
	}

	if len(b) < pos+4*akmCount {
		return &ri, errRSNTruncatedAKMList
	}
	// Additional validation: check if we have enough space for the current counts
	// Calculate minimum required space for what we've parsed so far
	minRequired := 6 + 2 + 4*pcCount + 2 + 4*akmCount // version + group + pairwise_count + pairwise + akm_count + akms
	if len(b) < minRequired {
		return &ri, errRSNTooSmallForCounts
	}

	ri.AKMs = make([]RSNAKM, 0, akmCount) // Pre-allocate with known capacity
	for range akmCount {
		sel := binary.BigEndian.Uint32(b[pos : pos+4])
		ri.AKMs = append(ri.AKMs, RSNAKM(sel))
		pos += 4
	}

	// Capabilities (optional)
	if len(b) >= pos+2 {
		ri.Capabilities = binary.LittleEndian.Uint16(b[pos : pos+2])
		pos += 2
	}

	// PMKID list – skip if present, with proper bounds checking
	if len(b) >= pos+2 {
		pmkCount := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
		pos += 2

		if pmkCount > 15 { // (253-10)/16 ≈ 15 (theoretical max with minimal overhead)
			return &ri, errRSNPMKIDCountTooLarge
		}

		// Check if we have enough bytes for all PMKIDs
		if len(b) < pos+16*pmkCount {
			return &ri, errRSNTruncatedPMKIDList
		}
		pos += 16 * pmkCount
	}

	// Group‑management cipher (optional, WPA3/802.11w)
	if len(b) >= pos+4 {
		gmCipherOUI := binary.BigEndian.Uint32(b[pos : pos+4])
		ri.GroupMgmtCipher = RSNCipher(gmCipherOUI)
	}

	return &ri, nil
}

// checkExtFeature Checks if a physical interface supports a extended feature
func (c *client) checkExtFeature(ifi *Interface, feature uint) (bool, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_WIPHY,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Flag(unix.NL80211_ATTR_SPLIT_WIPHY_DUMP, true)
		},
	)
	if err != nil {
		return false, err
	}

	var features []byte
found:
	for i := range msgs {
		attrs, err := netlink.UnmarshalAttributes(msgs[i].Data)
		if err != nil {
			return false, err
		}
		for _, a := range attrs {
			if a.Type == unix.NL80211_ATTR_EXT_FEATURES {
				features = a.Data
				break found
			}
		}
	}

	if feature/8 >= uint(len(features)) {
		return false, nil
	}

	return (features[feature/8]&(1<<(feature%8)) != 0), nil
}
