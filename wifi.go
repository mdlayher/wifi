package wifi

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// errInvalidIE is returned when one or more IEs are malformed.
var errInvalidIE = errors.New("invalid 802.11 information element")

// errInvalidBSSLoad is returned when BSSLoad IE has wrong length.
var errInvalidBSSLoad = errors.New("802.11 information element BSSLoad has wrong length")

// An InterfaceType is the operating mode of an Interface.
type InterfaceType int

const (
	// InterfaceTypeUnspecified indicates that an interface's type is unspecified
	// and the driver determines its function.
	InterfaceTypeUnspecified InterfaceType = iota

	// InterfaceTypeAdHoc indicates that an interface is part of an independent
	// basic service set (BSS) of client devices without a controlling access
	// point.
	InterfaceTypeAdHoc

	// InterfaceTypeStation indicates that an interface is part of a managed
	// basic service set (BSS) of client devices with a controlling access point.
	InterfaceTypeStation

	// InterfaceTypeAP indicates that an interface is an access point.
	InterfaceTypeAP

	// InterfaceTypeAPVLAN indicates that an interface is a VLAN interface
	// associated with an access point.
	InterfaceTypeAPVLAN

	// InterfaceTypeWDS indicates that an interface is a wireless distribution
	// interface, used as part of a network of multiple access points.
	InterfaceTypeWDS

	// InterfaceTypeMonitor indicates that an interface is a monitor interface,
	// receiving all frames from all clients in a given network.
	InterfaceTypeMonitor

	// InterfaceTypeMeshPoint indicates that an interface is part of a wireless
	// mesh network.
	InterfaceTypeMeshPoint

	// InterfaceTypeP2PClient indicates that an interface is a client within
	// a peer-to-peer network.
	InterfaceTypeP2PClient

	// InterfaceTypeP2PGroupOwner indicates that an interface is the group
	// owner within a peer-to-peer network.
	InterfaceTypeP2PGroupOwner

	// InterfaceTypeP2PDevice indicates that an interface is a device within
	// a peer-to-peer client network.
	InterfaceTypeP2PDevice

	// InterfaceTypeOCB indicates that an interface is outside the context
	// of a basic service set (BSS).
	InterfaceTypeOCB

	// InterfaceTypeNAN indicates that an interface is part of a near-me
	// area network (NAN).
	InterfaceTypeNAN
)

// String returns the string representation of an InterfaceType.
func (t InterfaceType) String() string {
	switch t {
	case InterfaceTypeUnspecified:
		return "unspecified"
	case InterfaceTypeAdHoc:
		return "ad-hoc"
	case InterfaceTypeStation:
		return "station"
	case InterfaceTypeAP:
		return "access point"
	case InterfaceTypeWDS:
		return "wireless distribution"
	case InterfaceTypeMonitor:
		return "monitor"
	case InterfaceTypeMeshPoint:
		return "mesh point"
	case InterfaceTypeP2PClient:
		return "P2P client"
	case InterfaceTypeP2PGroupOwner:
		return "P2P group owner"
	case InterfaceTypeP2PDevice:
		return "P2P device"
	case InterfaceTypeOCB:
		return "outside context of BSS"
	case InterfaceTypeNAN:
		return "near-me area network"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// An Interface is a WiFi network interface.
type Interface struct {
	// The index of the interface.
	Index int

	// The name of the interface.
	Name string

	// The hardware address of the interface.
	HardwareAddr net.HardwareAddr

	// The physical device that this interface belongs to.
	PHY int

	// The virtual device number of this interface within a PHY.
	Device int

	// The operating mode of the interface.
	Type InterfaceType

	// The interface's wireless frequency in MHz.
	Frequency int
}

// StationInfo contains statistics about a WiFi interface operating in
// station mode.
type StationInfo struct {
	// The hardware address of the station.
	HardwareAddr net.HardwareAddr

	// The time since the station last connected.
	Connected time.Duration

	// The time since wireless activity last occurred.
	Inactive time.Duration

	// The number of bytes received by this station.
	ReceivedBytes int

	// The number of bytes transmitted by this station.
	TransmittedBytes int

	// The number of packets received by this station.
	ReceivedPackets int

	// The number of packets transmitted by this station.
	TransmittedPackets int

	// The current data receive bitrate, in bits/second.
	ReceiveBitrate int

	// The current data transmit bitrate, in bits/second.
	TransmitBitrate int

	// The signal strength of the last received PPDU, in dBm.
	Signal int

	// The average signal strength, in dBm.
	SignalAverage int

	// The number of times the station has had to retry while sending a packet.
	TransmitRetries int

	// The number of times a packet transmission failed.
	TransmitFailed int

	// The number of times a beacon loss was detected.
	BeaconLoss int
}

// BSSLoad is an Information Element containing measurements of the load on the BSS.
type BSSLoad struct {
	// Version: Indicates the version of the BSS Load Element. Can be 1 or 2.
	Version int

	// StationCount: total number of STA currently associated with this BSS.
	StationCount uint16

	// ChannelUtilization: Percentage of time (linearly scaled 0 to 255) that the AP sensed the medium was busy. Calculated only for the primary channel.
	ChannelUtilization uint8

	// AvailableAdmissionCapacity: remaining amount of medium time availible via explicit admission controll in units of 32 us/s.
	AvailableAdmissionCapacity uint16
}

// String returns the string representation of a BSSLoad.
func (l BSSLoad) String() string {
	switch l.Version {
	case 1:
		return fmt.Sprintf("BSSLoad Version: %d    stationCount: %d    channelUtilization: %d/255     availableAdmissionCapacity: %d\n",
			l.Version, l.StationCount, l.ChannelUtilization, l.AvailableAdmissionCapacity,
		)
	case 2:
		return fmt.Sprintf("BSSLoad Version: %d    stationCount: %d    channelUtilization: %d/255     availableAdmissionCapacity: %d [*32us/s]\n",
			l.Version, l.StationCount, l.ChannelUtilization, l.AvailableAdmissionCapacity,
		)
	}
	return fmt.Sprintf("invalid BSSLoad Version: %d", l.Version)
}

// A BSS is an 802.11 basic service set.  It contains information about a wireless
// network associated with an Interface.
type BSS struct {
	// The service set identifier, or "network name" of the BSS.
	SSID string

	// BSSID: The BSS service set identifier.  In infrastructure mode, this is the
	// hardware address of the wireless access point that a client is associated
	// with.
	BSSID net.HardwareAddr

	// Frequency: The frequency used by the BSS, in MHz.
	Frequency int

	// BeaconInterval: The time interval between beacon transmissions for this BSS.
	BeaconInterval time.Duration

	// LastSeen: The time since the client last scanned this BSS's information.
	LastSeen time.Duration

	// Status: The status of the client within the BSS.
	Status BSSStatus

	// Load: The load element of the BSS (contains StationCount, ChannelUtilization and AvailableAdmissionCapacity).
	Load BSSLoad
}

// A BSSStatus indicates the current status of client within a BSS.
type BSSStatus int

const (
	// BSSStatusAuthenticated indicates that a client is authenticated with a BSS.
	BSSStatusAuthenticated BSSStatus = iota

	// BSSStatusAssociated indicates that a client is associated with a BSS.
	BSSStatusAssociated

	// BSSStatusIBSSJoined indicates that a client has joined an independent BSS.
	BSSStatusIBSSJoined
)

// String returns the string representation of a BSSStatus.
func (s BSSStatus) String() string {
	switch s {
	case BSSStatusAuthenticated:
		return "authenticated"
	case BSSStatusAssociated:
		return "associated"
	case BSSStatusIBSSJoined:
		return "IBSS joined"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// List of 802.11 Information Element types.
const (
	ieSSID    = 0
	ieBSSLoad = 11
)

// An ie is an 802.11 information element.
type ie struct {
	ID uint8
	// Length field implied by length of data
	Data []byte
}

// parseIEs parses zero or more ies from a byte slice.
// Reference:
//
//	https://www.safaribooksonline.com/library/view/80211-wireless-networks/0596100523/ch04.html#wireless802dot112-CHP-4-FIG-31
func parseIEs(b []byte) ([]ie, error) {
	var ies []ie
	var i int
	for len(b[i:]) != 0 {

		if len(b[i:]) < 2 {
			return nil, errInvalidIE
		}

		id := b[i]
		i++
		l := int(b[i])
		i++

		if len(b[i:]) < l {
			return nil, errInvalidIE
		}

		ies = append(ies, ie{
			ID:   id,
			Data: b[i : i+l],
		})

		i += l
	}

	return ies, nil
}

type SurveyInfo struct {
	// The frequency in MHz of the channel.
	Frequency int

	// The noise level in dBm.
	Noise int

	// The time the radio has spent on this channel.
	ChannelTime time.Duration

	// The time the radio has spent on this channel while it was active.
	ChannelTimeActive time.Duration

	// The time the radio has spent on this channel while it was busy.
	ChannelTimeBusy time.Duration

	// The time the radio has spent on this channel while it was busy with external traffic.
	ChannelTimeExtBusy time.Duration

	// The time the radio has spent on this channel receiving data from a BSS.
	ChannelTimeBssRx time.Duration

	// The time the radio has spent on this channel receiving data.
	ChannelTimeRx time.Duration

	// The time the radio has spent on this channel transmitting data.
	ChannelTimeTx time.Duration

	// The time the radio has spent on this channel while it was scanning.
	ChannelTimeScan time.Duration

	// Indicates if the channel is currently in use.
	InUse bool
}
