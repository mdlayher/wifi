package wifi

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestInterfaceTypeString(t *testing.T) {
	tests := []struct {
		t InterfaceType
		s string
	}{
		{
			t: InterfaceTypeUnspecified,
			s: "unspecified",
		},
		{
			t: InterfaceTypeAdHoc,
			s: "ad-hoc",
		},
		{
			t: InterfaceTypeStation,
			s: "station",
		},
		{
			t: InterfaceTypeAP,
			s: "access point",
		},
		{
			t: InterfaceTypeWDS,
			s: "wireless distribution",
		},
		{
			t: InterfaceTypeMonitor,
			s: "monitor",
		},
		{
			t: InterfaceTypeMeshPoint,
			s: "mesh point",
		},
		{
			t: InterfaceTypeP2PClient,
			s: "P2P client",
		},
		{
			t: InterfaceTypeP2PGroupOwner,
			s: "P2P group owner",
		},
		{
			t: InterfaceTypeP2PDevice,
			s: "P2P device",
		},
		{
			t: InterfaceTypeOCB,
			s: "outside context of BSS",
		},
		{
			t: InterfaceTypeNAN,
			s: "near-me area network",
		},
		{
			t: InterfaceTypeNAN + 1,
			s: "unknown(13)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if want, got := tt.s, tt.t.String(); want != got {
				t.Fatalf("unexpected interface type string:\n- want: %q\n-  got: %q",
					want, got)
			}
		})
	}
}

func TestBSSStatusString(t *testing.T) {
	tests := []struct {
		t BSSStatus
		s string
	}{
		{
			t: BSSStatusAuthenticated,
			s: "authenticated",
		},
		{
			t: BSSStatusAssociated,
			s: "associated",
		},
		{
			t: BSSStatusNotAssociated,
			s: "unassociated",
		},
		{
			t: BSSStatusIBSSJoined,
			s: "IBSS joined",
		},
		{
			t: 4,
			s: "unknown(4)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if want, got := tt.s, tt.t.String(); want != got {
				t.Fatalf("unexpected BSS status string:\n- want: %q\n-  got: %q",
					want, got)
			}
		})
	}
}

func Test_parseIEs(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		ies  []ie
		err  error
	}{
		{
			name: "empty",
		},
		{
			name: "too short",
			b:    []byte{0x00},
			err:  errInvalidIE,
		},
		{
			name: "length too long",
			b:    []byte{0x00, 0xff, 0x00},
			err:  errInvalidIE,
		},
		{
			name: "OK one",
			b:    []byte{0x00, 0x03, 'f', 'o', 'o'},
			ies: []ie{{
				ID:   0,
				Data: []byte("foo"),
			}},
		},
		{
			name: "OK three",
			b: []byte{
				0x00, 0x03, 'f', 'o', 'o',
				0x01, 0x00,
				0x02, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
			},
			ies: []ie{
				{
					ID:   0,
					Data: []byte("foo"),
				},
				{
					ID:   1,
					Data: []byte{},
				},
				{
					ID:   2,
					Data: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ies, err := parseIEs(tt.b)

			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}
			if err != nil {
				t.Logf("err: %v", err)
				return
			}

			if want, got := tt.ies, ies; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected ies:\n- want: %v\n-  got: %v",
					want, got)
			}
		})
	}
}

func TestRSNCipherString(t *testing.T) {
	tests := []struct {
		cipher RSNCipher
		want   string
	}{
		{RSNCipherUseGroup, "Use‑group"},
		{RSNCipherWEP40, "WEP‑40"},
		{RSNCipherTKIP, "TKIP"},
		{RSNCipherReserved3, "Reserved‑3"},
		{RSNCipherCCMP128, "CCMP‑128"},
		{RSNCipherWEP104, "WEP‑104"},
		{RSNCipherBIPCMAC128, "BIP‑CMAC‑128"},
		{RSNCipherGroupNotAllowed, "Group‑not‑allowed"},
		{RSNCipherGCMP128, "GCMP‑128"},
		{RSNCipherGCMP256, "GCMP‑256"},
		{RSNCipherCCMP256, "CCMP‑256"},
		{RSNCipherBIPGMAC128, "BIP‑GMAC‑128"},
		{RSNCipherBIPGMAC256, "BIP‑GMAC‑256"},
		{RSNCipherBIPCMAC256, "BIP‑CMAC‑256"},
		{RSNCipher(0x000FAC99), "Unknown-0x000FAC99"}, // Unknown cipher
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.cipher.String(); got != tt.want {
				t.Errorf("RSNCipher.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSNAKMString(t *testing.T) {
	tests := []struct {
		akm  RSNAKM
		want string
	}{
		{RSN_AKM_RESERVED_0, "Reserved‑0"},
		{RSN_AKM_8021X, "802.1X"},
		{RSN_AKM_PSK, "PSK"},
		{RSN_AKM_FT_8021X, "FT‑802.1X"},
		{RSN_AKM_FT_PSK, "FT‑PSK"},
		{RSN_AKM_8021X_SHA256, "802.1X‑SHA256"},
		{RSN_AKM_PSK_SHA256, "PSK‑SHA256"},
		{RSN_AKM_TDLS, "TDLS"},
		{RSN_AKM_SAE, "SAE"},
		{RSN_AKM_FT_SAE, "FT‑SAE"},
		{RSN_AKM_AP_PEERKEY, "AP‑PeerKey"},
		{RSN_AKM_8021X_SUITE_B, "802.1X‑Suite‑B"},
		{RSN_AKM_8021X_CNSA, "802.1X‑CNSA"},
		{RSN_AKM_FT_8021X_SHA384, "FT‑802.1X‑SHA384"},
		{RSN_AKM_FILS_SHA256, "FILS‑SHA256"},
		{RSN_AKM_FILS_SHA384, "FILS‑SHA384"},
		{RSN_AKM_FT_FILS_SHA256, "FT‑FILS‑SHA256"},
		{RSN_AKM_FT_FILS_SHA384, "FT‑FILS‑SHA384"},
		{RSN_AKM_RESERVED_18, "Reserved‑18"},
		{RSN_AKM_FT_PSK_SHA384, "FT‑PSK‑SHA384"},
		{RSN_AKM_PSK_SHA384, "PSK‑SHA384"},
		{RSNAKM(0x000FAC99), "Unknown-0x000FAC99"}, // Unknown AKM
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.akm.String(); got != tt.want {
				t.Errorf("RSNAKM.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSNInfoIsInitialized(t *testing.T) {
	tests := []struct {
		name string
		rsn  RSNInfo
		want bool
	}{
		{
			name: "uninitialized",
			rsn:  RSNInfo{},
			want: false,
		},
		{
			name: "initialized_version_1",
			rsn:  RSNInfo{Version: 1},
			want: true,
		},
		{
			name: "initialized_version_2",
			rsn:  RSNInfo{Version: 2},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rsn.IsInitialized(); got != tt.want {
				t.Errorf("RSNInfo.IsInitialized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSNInfoString(t *testing.T) {
	tests := []struct {
		name string
		rsn  RSNInfo
		want string
	}{
		{
			name: "uninitialized",
			rsn:  RSNInfo{},
			want: "",
		},
		{
			name: "basic_wpa2",
			rsn: RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSN_AKM_PSK},
			},
			want: "RSN v1  Group:CCMP‑128  Pairwise:[CCMP‑128]  AKM:[PSK]",
		},
		{
			name: "wpa3_multiple_ciphers",
			rsn: RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherGCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherGCMP128, RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSN_AKM_SAE, RSN_AKM_PSK},
			},
			want: "RSN v1  Group:GCMP‑128  Pairwise:[GCMP‑128 CCMP‑128]  AKM:[SAE PSK]",
		},
		{
			name: "enterprise_with_ft",
			rsn: RSNInfo{
				Version:         1,
				GroupCipher:     RSNCipherCCMP128,
				PairwiseCiphers: []RSNCipher{RSNCipherCCMP128},
				AKMs:            []RSNAKM{RSN_AKM_8021X, RSN_AKM_FT_8021X},
			},
			want: "RSN v1  Group:CCMP‑128  Pairwise:[CCMP‑128]  AKM:[802.1X FT‑802.1X]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rsn.String(); got != tt.want {
				t.Errorf("RSNInfo.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSNErrorHierarchy(t *testing.T) {
	// Test that specific errors wrap the base error and basic functionality
	tests := []struct {
		name        string
		err         error
		description string
	}{
		{"DataTooLarge", errRSNDataTooLarge, "data exceeds maximum size"},
		{"TooShort", errRSNTooShort, "IE too short"},
		{"InvalidVersion", errRSNInvalidVersion, "invalid version"},
		{"TruncatedPairwiseCount", errRSNTruncatedPairwiseCount, "truncated before pairwise count"},
		{"PairwiseCipherCountTooLarge", errRSNPairwiseCipherCountTooLarge, "pairwise cipher count too large"},
		{"TruncatedPairwiseList", errRSNTruncatedPairwiseList, "truncated in pairwise list"},
		{"AKMCountTooLarge", errRSNAKMCountTooLarge, "AKM count too large"},
		{"TruncatedAKMList", errRSNTruncatedAKMList, "truncated in AKM list"},
		{"TooSmallForCounts", errRSNTooSmallForCounts, "too small for declared cipher/AKM counts"},
		{"PMKIDCountTooLarge", errRSNPMKIDCountTooLarge, "PMKID count too large"},
		{"TruncatedPMKIDList", errRSNTruncatedPMKIDList, "truncated in PMKID list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the specific error wraps the base error (errors.Is functionality)
			if !errors.Is(tt.err, errRSNParse) {
				t.Errorf("errors.Is(%v, errRSNParse) = false, want true", tt.err)
			}

			// Test that the specific error is still identifiable as itself
			if !errors.Is(tt.err, tt.err) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.err)
			}

			// Test that specific errors don't match other specific errors
			if tt.err != errRSNDataTooLarge && errors.Is(tt.err, errRSNDataTooLarge) {
				t.Errorf("error %v should not match errRSNDataTooLarge", tt.err)
			}

			// Test that RSN errors don't match non-RSN errors
			if errors.Is(tt.err, errInvalidIE) {
				t.Errorf("RSN error %v should not match errInvalidIE", tt.err)
			}

			// Test that error message is properly formatted
			errMsg := tt.err.Error()
			if errMsg == "" {
				t.Errorf("error message is empty")
			}

			// Verify error message contains both base and specific parts
			if !strings.Contains(errMsg, errRSNParse.Error()) {
				t.Errorf("error message should contain %q, got: %q", errRSNParse.Error(), errMsg)
			}
			if !strings.Contains(errMsg, tt.description) {
				t.Errorf("error message should contain %q, got: %q", tt.description, errMsg)
			}
		})
	}

	// Test that base error doesn't match specific errors
	t.Run("Base error isolation", func(t *testing.T) {
		if errors.Is(errRSNParse, errRSNDataTooLarge) {
			t.Error("base error should not match specific errors")
		}
	})
}
