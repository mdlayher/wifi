package wifi

import (
	"testing"
)

func TestClientStationInfoNotStation(t *testing.T) {
	_, got := (&Client{}).StationInfo(&Interface{
		Type: InterfaceTypeAP,
	})

	if want := errNotStation; want != got {
		t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
			want, got)
	}
}
