//go:build linux
// +build linux

package wifi_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

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

func execN(t *testing.T, n int, expect []string, workerID int) {
	c := testClient(t)

	names := make(map[string]int)
	for i := 0; i < n; i++ {
		ifis, err := c.Interfaces()
		if err != nil {
			panicf("[worker_id %d; iteration %d] failed to retrieve interfaces: %v", workerID, i, err)
		}

		for _, ifi := range ifis {
			if ifi.Name == "" || ifi.Type != wifi.InterfaceTypeStation {
				continue
			}

			if _, err := c.StationInfo(ifi); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					panicf("[worker_id %d; iteration %d] failed to retrieve station info for device %s: %v", workerID, i, ifi.Name, err)
				}
			}

			if _, err := c.SurveyInfo(ifi); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					panicf("[worker_id %d; iteration %d] failed to retrieve survey info for device %s: %v", workerID, i, ifi.Name, err)
				}
			}

			names[ifi.Name]++
		}
	}

	for _, e := range expect {
		nn, ok := names[e]
		if !ok {
			panicf("[worker_id %d] did not find interface %q during test", workerID, e)
		}
		if nn != n {
			panicf("[worker_id %d] wanted to find %q %d times, found %d", workerID, e, n, nn)
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

func TestClient_AccessPoints(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skipf("skipping, must be run as root")
	}

	c, err := wifi.New()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ifis, err := c.Interfaces()
	if err != nil {
		t.Fatalf("failed to retrieve interfaces: %v", err)
	}

	for _, ifi := range ifis {
		if ifi.Name == "" || ifi.Type != wifi.InterfaceTypeStation {
			continue
		}

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
		defer cancel()

		err = c.Scan(ctx, ifi)
		if err != nil {
			t.Fatalf("failed to scan access points for device %s: %v", ifi.Name, err)
		}

		_, err := c.AccessPoints(ifi)
		if err != nil {
			t.Fatalf("failed to retrieve access points for device %s: %v", ifi.Name, err)
		}

	}
}
