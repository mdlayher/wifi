package wifi

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

func TestClientIntegrationConcurrent(t *testing.T) {
	const (
		workers    = 16
		iterations = 10000
	)

	c := mustNew(t)
	ifis, err := c.Interfaces()
	if err != nil {
		t.Fatalf("failed to retrieve interfaces: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("failed to close client: %v", err)
	}

	if len(ifis) == 0 {
		t.Skip("found no wifi interfaces, skipping")
	}

	names := make([]string, 0)
	for _, ifi := range ifis {
		if ifi.Name == "" || ifi.Type != InterfaceTypeStation {
			continue
		}

		names = append(names, ifi.Name)
	}

	t.Logf("workers: %d, iterations: %d, interfaces: %v",
		workers, iterations, names)

	clients := make([]*Client, 0, workers)
	for i := 0; i < workers; i++ {
		clients = append(clients, mustNew(t))
	}

	var wg sync.WaitGroup
	wg.Add(workers)

	for _, c := range clients {
		go execN(&wg, c, iterations, names)
	}

	wg.Wait()
}

func mustNew(t *testing.T) *Client {
	c, err := New()
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("wifi data not available, skipping")
		}
		if err == errUnimplemented {
			t.Skip(err)
		}

		t.Fatalf("failed to access wifi data: %v", err)
	}

	return c
}

func execN(wg *sync.WaitGroup, c *Client, n int, expect []string) {
	names := make(map[string]int, 0)

	for i := 0; i < n; i++ {
		ifis, err := c.Interfaces()
		if err != nil {
			panic(fmt.Sprintf("failed to retrieve interfaces: %v", err))
		}

		for _, ifi := range ifis {
			if ifi.Name == "" || ifi.Type != InterfaceTypeStation {
				continue
			}

			if _, err := c.StationInfo(ifi); err != nil {
				if !os.IsNotExist(err) {
					panic(fmt.Sprintf("failed to retrieve station info for device %s: %v", ifi.Name, err))
				}
			}

			names[ifi.Name]++
		}
	}

	for _, e := range expect {
		nn, ok := names[e]
		if !ok {
			panic(fmt.Sprintf("did not find interface %q during test", e))
		}
		if nn != n {
			panic(fmt.Sprintf("wanted to find %q %d times, found %d", e, n, nn))
		}
	}

	wg.Done()
}
