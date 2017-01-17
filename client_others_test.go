//+build !linux

package wifi

import (
	"testing"
)

func TestOthers_clientUnimplemented(t *testing.T) {
	c := &client{}
	want := errUnimplemented

	if _, got := newClient(); want != got {
		t.Fatalf("unexpected error during newClient:\n- want: %v\n-  got: %v",
			want, got)
	}

	if _, got := c.Interfaces(); want != got {
		t.Fatalf("unexpected error during c.Interfaces\n- want: %v\n-  got: %v",
			want, got)
	}

	if _, got := c.BSS(nil); want != got {
		t.Fatalf("unexpected error during c.BSS\n- want: %v\n-  got: %v",
			want, got)
	}

	if _, got := c.StationInfo(nil); want != got {
		t.Fatalf("unexpected error during c.StationInfo\n- want: %v\n-  got: %v",
			want, got)
	}

	if got := c.Close(); want != got {
		t.Fatalf("unexpected error during c.Close:\n- want: %v\n-  got: %v",
			want, got)
	}
}
