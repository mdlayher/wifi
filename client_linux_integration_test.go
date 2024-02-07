//go:build linux
// +build linux

package wifi_test

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/mdlayher/wifi"
)

func TestIntegrationLinuxConcurrent(t *testing.T) {
	const (
		workers    = 4
		iterations = 1000
	)

	c := testClient(t)
	ifis, err := c.Interfaces()
	if err != nil {
		t.Fatalf("failed to retrieve interfaces: %v", err)
	}
	if len(ifis) == 0 {
		t.Skip("skipping, found no WiFi interfaces")
	}

	var names []string
	for _, ifi := range ifis {
		if ifi.Name == "" || ifi.Type != wifi.InterfaceTypeStation {
			continue
		}

		names = append(names, ifi.Name)
	}

	t.Logf("workers: %d, iterations: %d, interfaces: %v",
		workers, iterations, names)

	var wg sync.WaitGroup
	wg.Add(workers)
	defer wg.Wait()

	for i := 0; i < workers; i++ {
		go func(differentI int) {
			defer wg.Done()
			execN(t, iterations, names, differentI)
		}(i)
	}
}

func execN(t *testing.T, n int, expect []string, worker_id int) {
	c := testClient(t)

	names := make(map[string]int)
	for i := 0; i < n; i++ {
		ifis, err := c.Interfaces()
		if err != nil {
			panicf("[worker_id %d; iteration %d] failed to retrieve interfaces: %v", worker_id, i, err)
		}

		for _, ifi := range ifis {
			if ifi.Name == "" || ifi.Type != wifi.InterfaceTypeStation {
				continue
			}

			if _, err := c.StationInfo(ifi); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					panicf("[worker_id %d; iteration %d] failed to retrieve station info for device %s: %v", worker_id, i, ifi.Name, err)
				}
			}

			names[ifi.Name]++
		}
	}

	for _, e := range expect {
		nn, ok := names[e]
		if !ok {
			panicf("[worker_id %d] did not find interface %q during test", worker_id, e)
		}
		if nn != n {
			panicf("[worker_id %d] wanted to find %q %d times, found %d", worker_id, e, n, nn)
		}
	}
}

func testClient(t *testing.T) *wifi.Client {
	t.Helper()

	c, err := wifi.New()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("skipping, nl80211 not found: %v", err)
		}

		t.Fatalf("failed to create client: %v", err)
	}

	t.Cleanup(func() { _ = c.Close() })
	return c
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
