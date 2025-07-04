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

// RSN (Robust Security Network) Information Element parsing errors
var (
	// Base error for all RSN parsing errors
	errRSNParse = errors.New("RSN IE parsing error")

	// Specific RSN parsing errors that wrap the base error
	errRSNDataTooLarge                = fmt.Errorf("%w: data exceeds maximum size of 253 octets", errRSNParse)
	errRSNTooShort                    = fmt.Errorf("%w: IE too short", errRSNParse)
	errRSNInvalidVersion              = fmt.Errorf("%w: invalid version 0", errRSNParse)
	errRSNTruncatedPairwiseCount      = fmt.Errorf("%w: truncated before pairwise count", errRSNParse)
	errRSNPairwiseCipherCountTooLarge = fmt.Errorf("%w: pairwise cipher count too large", errRSNParse)
	errRSNTruncatedPairwiseList       = fmt.Errorf("%w: truncated in pairwise list", errRSNParse)
	errRSNAKMCountTooLarge            = fmt.Errorf("%w: AKM count too large", errRSNParse)
	errRSNTruncatedAKMList            = fmt.Errorf("%w: truncated in AKM list", errRSNParse)
	errRSNTooSmallForCounts           = fmt.Errorf("%w: too small for declared cipher/AKM counts", errRSNParse)
	errRSNPMKIDCountTooLarge          = fmt.Errorf("%w: PMKID count too large", errRSNParse)
	errRSNTruncatedPMKIDList          = fmt.Errorf("%w: truncated in PMKID list", errRSNParse)
)

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
	// The interface that this station is associated with.
	InterfaceIndex int

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

	// RSN Robust Security Network Information Element (IEEE 802.11 Element ID 48)
	RSN RSNInfo
}

// A BSSStatus indicates the current status of client within a BSS.
type BSSStatus int

const (
	// BSSStatusAuthenticated indicates that a client is authenticated with a BSS.
	BSSStatusAuthenticated BSSStatus = iota

	// BSSStatusAssociated indicates that a client is associated with a BSS.
	BSSStatusAssociated

	// BSSStatusNotAssociated indicates that a client is not associated with a BSS.
	BSSStatusNotAssociated

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
	case BSSStatusNotAssociated:
		return "unassociated"
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
	ieRSN     = 48 // Robust Security Network
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
	// The interface that this station is associated with.
	InterfaceIndex int

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

// RSNCipher represents a cipher suite in RSN IE.
// Values correspond to OUIs (00-0F-AC-XX) in the wire format as defined in
// IEEE 802.11-2020 standard, section 9.4.2.24.2 (Cipher Suites).
type RSNCipher uint32

const (
	RSNCipherUseGroup        RSNCipher = 0x000FAC00 // Use group cipher suite
	RSNCipherWEP40           RSNCipher = 0x000FAC01 // WEP-40 (insecure, legacy)
	RSNCipherTKIP            RSNCipher = 0x000FAC02 // TKIP (insecure, deprecated)
	RSNCipherReserved3       RSNCipher = 0x000FAC03 // Reserved
	RSNCipherCCMP128         RSNCipher = 0x000FAC04 // CCMP-128 (AES) - WPA2
	RSNCipherWEP104          RSNCipher = 0x000FAC05 // WEP-104 (insecure, legacy)
	RSNCipherBIPCMAC128      RSNCipher = 0x000FAC06 // BIP-CMAC-128 (802.11w MFP/PMF)
	RSNCipherGroupNotAllowed RSNCipher = 0x000FAC07 // Group addressed traffic not allowed
	RSNCipherGCMP128         RSNCipher = 0x000FAC08 // GCMP-128 (AES-GCMP) - WPA3
	RSNCipherGCMP256         RSNCipher = 0x000FAC09 // GCMP-256 (AES-GCMP) - WPA3-Enterprise
	RSNCipherCCMP256         RSNCipher = 0x000FAC0A // CCMP-256 (AES, 256-bit key)
	RSNCipherBIPGMAC128      RSNCipher = 0x000FAC0B // BIP-GMAC-128
	RSNCipherBIPGMAC256      RSNCipher = 0x000FAC0C // BIP-GMAC-256
	RSNCipherBIPCMAC256      RSNCipher = 0x000FAC0D // BIP-CMAC-256
)

// String returns the human-readable name of the RSN cipher.
func (c RSNCipher) String() string {
	switch c {
	case RSNCipherUseGroup:
		return "Use‑group"
	case RSNCipherWEP40:
		return "WEP‑40"
	case RSNCipherTKIP:
		return "TKIP"
	case RSNCipherReserved3:
		return "Reserved‑3"
	case RSNCipherCCMP128:
		return "CCMP‑128"
	case RSNCipherWEP104:
		return "WEP‑104"
	case RSNCipherBIPCMAC128:
		return "BIP‑CMAC‑128"
	case RSNCipherGroupNotAllowed:
		return "Group‑not‑allowed"
	case RSNCipherGCMP128:
		return "GCMP‑128"
	case RSNCipherGCMP256:
		return "GCMP‑256"
	case RSNCipherCCMP256:
		return "CCMP‑256"
	case RSNCipherBIPGMAC128:
		return "BIP‑GMAC‑128"
	case RSNCipherBIPGMAC256:
		return "BIP‑GMAC‑256"
	case RSNCipherBIPCMAC256:
		return "BIP‑CMAC‑256"
	default:
		return fmt.Sprintf("Unknown-0x%08X", uint32(c))
	}
}

// RSNAKM represents an Authentication and Key Management suite in RSN IE.
// Values correspond to OUIs (00-0F-AC-XX) in the wire format as defined in
// IEEE 802.11-2020 standard, section 9.4.2.24.3 (AKM Suites).
type RSNAKM uint32

// RSN AKM suite constants (Wi-Fi Alliance OUI: 00-0F-AC)
const (
	RSNAkmReserved0     RSNAKM = 0x000FAC00 // Reserved
	RSNAkm8021X         RSNAKM = 0x000FAC01 // 802.1X (WPA-Enterprise)
	RSNAkmPSK           RSNAKM = 0x000FAC02 // PSK (WPA2-Personal)
	RSNAkmFT8021X       RSNAKM = 0x000FAC03 // FT-802.1X (Fast BSS transition with EAP)
	RSNAkmFTPSK         RSNAKM = 0x000FAC04 // FT-PSK (Fast BSS transition with PSK)
	RSNAkm8021XSHA256   RSNAKM = 0x000FAC05 // 802.1X-SHA256 (WPA2 with SHA256 auth)
	RSNAkmPSKSHA256     RSNAKM = 0x000FAC06 // PSK-SHA256 (WPA2-PSK with SHA256)
	RSNAkmTDLS          RSNAKM = 0x000FAC07 // TDLS TPK handshake
	RSNAkmSAE           RSNAKM = 0x000FAC08 // SAE (WPA3-Personal)
	RSNAkmFTSAE         RSNAKM = 0x000FAC09 // FT-SAE (WPA3-Personal with Fast Roaming)
	RSNAkmAPPeerKey     RSNAKM = 0x000FAC0A // APPeerKey Authentication with SHA-256
	RSNAkm8021XSuiteB   RSNAKM = 0x000FAC0B // 802.1X using Suite B compliant EAP (SHA-256)
	RSNAkm8021XCNSA     RSNAKM = 0x000FAC0C // 802.1X using CNSA Suite compliant EAP (SHA-384)
	RSNAkmFT8021XSHA384 RSNAKM = 0x000FAC0D // FT-802.1X using SHA-384
	RSNAkmFILSSHA256    RSNAKM = 0x000FAC0E // FILS key management using SHA-256
	RSNAkmFILSSHA384    RSNAKM = 0x000FAC0F // FILS key management using SHA-384
	RSNAkmFTFILSSHA256  RSNAKM = 0x000FAC10 // FT authentication over FILS with SHA-256
	RSNAkmFTFILSSHA384  RSNAKM = 0x000FAC11 // FT authentication over FILS with SHA-384
	RSNAkmReserved18    RSNAKM = 0x000FAC12 // Reserved
	RSNAkmFTPSKSHA384   RSNAKM = 0x000FAC13 // FT-PSK using SHA-384
	RSNAkmPSKSHA384     RSNAKM = 0x000FAC14 // PSK using SHA-384
)

// String returns the human-readable name of the RSN AKM.
func (a RSNAKM) String() string {
	switch a {
	case RSNAkmReserved0:
		return "Reserved‑0"
	case RSNAkm8021X:
		return "802.1X"
	case RSNAkmPSK:
		return "PSK"
	case RSNAkmFT8021X:
		return "FT‑802.1X"
	case RSNAkmFTPSK:
		return "FT‑PSK"
	case RSNAkm8021XSHA256:
		return "802.1X‑SHA256"
	case RSNAkmPSKSHA256:
		return "PSK‑SHA256"
	case RSNAkmTDLS:
		return "TDLS"
	case RSNAkmSAE:
		return "SAE"
	case RSNAkmFTSAE:
		return "FT‑SAE"
	case RSNAkmAPPeerKey:
		return "AP‑PeerKey"
	case RSNAkm8021XSuiteB:
		return "802.1X‑Suite‑B"
	case RSNAkm8021XCNSA:
		return "802.1X‑CNSA"
	case RSNAkmFT8021XSHA384:
		return "FT‑802.1X‑SHA384"
	case RSNAkmFILSSHA256:
		return "FILS‑SHA256"
	case RSNAkmFILSSHA384:
		return "FILS‑SHA384"
	case RSNAkmFTFILSSHA256:
		return "FT‑FILS‑SHA256"
	case RSNAkmFTFILSSHA384:
		return "FT‑FILS‑SHA384"
	case RSNAkmReserved18:
		return "Reserved‑18"
	case RSNAkmFTPSKSHA384:
		return "FT‑PSK‑SHA384"
	case RSNAkmPSKSHA384:
		return "PSK‑SHA384"
	default:
		return fmt.Sprintf("Unknown-0x%08X", uint32(a))
	}
}

// Robust Security Network Information Element
// The RSN IE structure is defined in IEEE 802.11-2020 standard, section 9.4.2.24 (page 1051) .
type RSNInfo struct {
	Version         uint16
	GroupCipher     RSNCipher   // Group cipher suite
	PairwiseCiphers []RSNCipher // Pairwise cipher suites
	AKMs            []RSNAKM    // Authentication and Key Management suites
	Capabilities    uint16      // RSN capability flags
	GroupMgmtCipher RSNCipher   // Group management cipher (present only with WPA3/802.11w)
}

func (r RSNInfo) IsInitialized() bool {
	return r.Version != 0
}

func (r RSNInfo) String() string {
	if !r.IsInitialized() {
		return ""
	}

	// Convert pairwise ciphers to strings
	pairwiseNames := make([]string, len(r.PairwiseCiphers))
	for i, cipher := range r.PairwiseCiphers {
		pairwiseNames[i] = cipher.String()
	}

	// Convert AKMs to strings
	akmNames := make([]string, len(r.AKMs))
	for i, akm := range r.AKMs {
		akmNames[i] = akm.String()
	}

	return fmt.Sprintf(
		"RSN v%d  Group:%s  Pairwise:%v  AKM:%v",
		r.Version, r.GroupCipher.String(), pairwiseNames, akmNames)
}
