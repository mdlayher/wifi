package wifi

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
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
	case InterfaceTypeAPVLAN:
		return "access point/VLAN"
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
	if l.Version == 1 {
		return fmt.Sprintf("BSSLoad Version: %d    stationCount: %d    channelUtilization: %d/255     availableAdmissionCapacity: %d\n",
			l.Version, l.StationCount, l.ChannelUtilization, l.AvailableAdmissionCapacity,
		)
	} else if l.Version == 2 {
		return fmt.Sprintf("BSSLoad Version: %d    stationCount: %d    channelUtilization: %d/255     availableAdmissionCapacity: %d [*32us/s]\n",
			l.Version, l.StationCount, l.ChannelUtilization, l.AvailableAdmissionCapacity,
		)
	} else {
		return fmt.Sprintf("invalid BSSLoad Version: %d", l.Version)
	}
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

// A PHY represents the physical attributes of a wireless device.
type PHY struct {
	// The index of the interface.
	Index int

	// The name of the interface.
	Name string

	// The interface types this device supports.
	SupportedIftypes []InterfaceType

	// The software-only interface types this device supports.
	SoftwareIftypes []InterfaceType

	// An array of attributes related to each radio frequency band.
	BandAttributes []BandAttributes

	// A description of what combinations of interfaces the device can
	// support running simultaneously, on virtual MACs.
	InterfaceCombinations []InterfaceCombination

	// All the attributes the kernel has told us about, but we haven't
	// parsed.
	Extra map[uint16][]byte
}

// BandAttributes represent the RF band-specific attributes.
type BandAttributes struct {
	// High Throughput (802.11n) device capabilities (nil if not supported).
	HTCapabilities *HTCapabilities

	// Very High Throughput (802.11ac) device capabilities (nil if not supported).
	VHTCapabilities *VHTCapabilities

	// Minimum spacing between A-MPDU frames.  Used for both HT and VHT
	// capable devices.
	MinRxAMPDUSpacing time.Duration

	// Per-frequency (channel) attributes.
	FrequencyAttributes []FrequencyAttrs

	// Per-bitrate attributes.
	BitrateAttributes []BitrateAttrs
}

// HTCapabilities represents 802.11n (High Throughput) capabilities.  This group
// of attributes is specific to each band of frequencies.  Failure to support
// any given attribute may be due to lack support in the driver or the firmware,
// not only in the hardware.  Some of them may also be overridden during station
// association.
//
// The fields represent those in the HT Capabilities element (802.11-2016,
// 9.4.2.56).  Notably missing is information about the device's Spatial
// Multiplexing Power Save (SMPS) capability.  SMPS support must be determined
// by retrieving the device feature flags (not yet supported).
type HTCapabilities struct {
	// Device supports Low Density Parity Check codes.
	RxLDPC bool

	// Device supports 40MHz channels (in addition to 20MHz channels).
	CW40 bool

	// Device supports HT Greenfield (802.11n-only) mode, in which a/b/g
	// frames will be ignored.
	HTGreenfield bool

	// Device supports short guard intervals in 20MHz channels.
	SGI20 bool

	// Device supports short guard intervals in 40MHz channels.
	SGI40 bool

	// Device supports Space-Time Block Coding transmission.
	TxSTBC bool

	// Number of STBC receive streams supported by the device.  Valid values
	// are 0-3.
	RxSTBCStreams uint8

	// Device supports delayed Block Ack frames when acknowledging an
	// A-MPDU.
	HTDelayedBlockAck bool

	// Device supports long (7935 bytes) maximum A-MSDU length, compared to
	// standard 3839 bytes.
	LongMaxAMSDULength bool

	// Device supports DSSS/CCK in 40MHz channels.
	DSSSCCKHT40 bool

	// (2.4GHz) Band cannot tolerate 40MHz channels because someone has
	// requested it support 20MHz channels.
	FortyMhzIntolerant bool

	// Device supports L-SIG (non-HT) Transmit Oppportunity protection.
	LSIGTxOPProtection bool

	// Maximum receivable A-MPDU (Aggregated MAC Protocol Data Unit) frame
	// size.
	MaxRxAMPDULength int

	// Supported MCS for HT mode
	// Todo:
	// - Parse them are according to Section 7.3.2.56.4 IEEE 80211n
	SupportedMCS [16]byte
}

// VHTCapabilities represents 802.11ac (Very High Throughput) capabilities.
//
// The fields represent those in the VHT Capabilities element (802.11-2020,
// 9.4.2.157).
type VHTCapabilities struct {
	// Maximum MPDU length supported by the device.
	MaxMPDULength int

	// Device supports 160MHz channel width.
	VHT160 bool

	// Device supports 80+80MHz channel width (non-contiguous 160MHz) along with 160MHz channel.
	VHT8080 bool

	// Device supports receiving Low Density Parity Check codes.
	RXLDPC bool

	// Device supports short guard intervals in 80MHz channels.
	ShortGI80 bool

	// Device supports short guard intervals in 160MHz and 80+80MHz channels.
	ShortGI160 bool

	// Device supports transmission of at least 2x1 Space-Time Block Coding transmission.
	TXSTBC bool

	// Number of STBC receive streams supported by the device. Valid values are 0-4.
	RXSTBC int

	// Device supports SU (Single User) Beamforming as a transmitter.
	SuBeamFormer bool

	// Device supports SU (Single User) Beamforming as a receiver.
	SuBeamFormee bool

	// Number of sounding antennas supported by the device for SU Beamforming transmission.
	BFAntenna int

	// Maximum sounding dimensions supported by the device for SU Beamforming.
	SoundingDimension int

	// Device supports MU (Multi-User) Beamforming as a transmitter.
	MuBeamformer bool

	// Device supports MU (Multi-User) Beamforming as a receiver.
	MuBeamformee bool

	// Device supports VHT TXOP power save mode.
	VTHTXOPPS bool

	// Device supports HT Control field when operating in VHT mode.
	HTCVHT bool

	// Maximum A-MPDU (Aggregated MAC Protocol Data Unit) frame size supported by the device.
	MaxAMPDU int

	// Device supports VHT Link Adaptation capabilities. Valid values
	// specify the type of link adaptation supported (e.g., no feedback,
	// unsolicited feedback, or both).
	VHTLinkAdapt int

	// Device supports receive antenna pattern consistency.
	RXAntennaPattern bool

	// Device supports transmit antenna pattern consistency.
	TXAntennaPattern bool

	//Indicates whether the STA is capable of interpreting the Extended NSS BW
	//Support subfield of the VHT Capabilities Information field.
	ExtendedNSSBW int

	// Supported MCS for VHT mode
	// Todo:
	// - Parse them according to Section 8.4.2.160.3 IEEE Std 80211ac-2013
	SupportedMCS [8]byte
}

// FrequencyAttrs represents the attributes of a WiFi frequency/channel.
type FrequencyAttrs struct {
	// Frequency is the radio frequency in MHz.
	Frequency int

	// Disabled indicates that the channel is disabled due to regulatory
	// requirements.
	Disabled bool

	// NoIR indicates that no mechanisms that initiate radiation are
	// permitted on this channel.
	NoIR bool

	// RadarDetection indicates that radar detection is mandatory on this
	// channel.
	RadarDetection bool

	// MaxTxPower gives the maximum transmission power in mBm (100 * dBm).
	MaxTxPower float32
}

// BitrateAttrs represents the attributes of a bitrate.
type BitrateAttrs struct {
	// Bitrate is the bitrate in units of 100kbps.
	Bitrate float32

	// ShortPreamble indicates that a short preamble is supported in the
	// 2.4GHz band.
	ShortPreamble bool
}

// InterfaceCombination represents a group of valid combinations of interface
// types which can be simultaneously supported on a device.
type InterfaceCombination struct {
	CombinationLimits []InterfaceCombinationLimit

	// Total is the maximum number of interfaces that can be created in this
	// group.
	Total int

	// NumChannels is the number of different channels which may be used in
	// this group.
	NumChannels int

	// StaApBiMatch indicates that beacon intervals within this group must
	// all be the same, regardless of interface type.
	StaApBiMatch bool
}

// InterfaceCombinationLimit represents a single combination of interface types
// which may be run simultaneously on a device.
type InterfaceCombinationLimit struct {
	InterfaceTypes []InterfaceType

	// Max is the maximum number of interfaces that can be chosen from the
	// set of interface types in InterfaceTypes.
	Max int
}

// FrequencyToChannel returns the channel number given the frequency in MHz, as
// defined by IEEE802.11-2007, 17.3.8.3.2 and Annex J.
func FrequencyToChannel(freq int) int {
	if freq == 2484 {
		return 14
	} else if freq < 2484 {
		return (freq - 2407) / 5
	} else if freq >= 4910 && freq <= 4980 {
		return (freq - 4000) / 5
	} else if freq <= 45000 {
		return (freq - 5000) / 5
	} else if freq >= 58320 && freq <= 64800 {
		return (freq - 56160) / 2160
	} else {
		return 0
	}
}

// Constants representing the standard WiFi frequency bands.
const (
	Band2GHz  = unix.NL80211_BAND_2GHZ
	Band5GHz  = unix.NL80211_BAND_5GHZ
	Band60GHz = unix.NL80211_BAND_60GHZ
)

// ChannelToFrequency returns the frequency given the channel number and the
// band, as there are overlapping channel numbers between bands.
func ChannelToFrequency(channel int, band int) int {
	if channel <= 0 {
		return 0
	}

	switch band {
	case Band2GHz:
		if channel == 14 {
			return 2484
		} else if channel < 14 {
			return 2407 + channel*5
		}
	case Band5GHz:
		if channel >= 182 && channel <= 196 {
			return 4000 + channel*5
		}
		return 5000 + channel*5
	case Band60GHz:
		if channel < 5 {
			return 56160 + channel*2160
		}
	}
	return 0
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
	for {
		if len(b[i:]) == 0 {
			break
		}
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
