package wifi

import (
	"reflect"
	"testing"
)

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
			t: BSSStatusIBSSJoined,
			s: "IBSS joined",
		},
		{
			t: 3,
			s: "unknown(3)",
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
