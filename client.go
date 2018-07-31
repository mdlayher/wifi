package wifi

import (
	"fmt"
	"runtime"
)

var (
	// errUnimplemented is returned by all functions on platforms that
	// do not have package wifi implemented.
	errUnimplemented = fmt.Errorf("package wifi not implemented on %s/%s",
		runtime.GOOS, runtime.GOARCH)
)

// A Client is a type which can access WiFi device actions and statistics
// using operating system-specific operations.
type Client struct {
	c osClient
}

// New creates a new Client.
func New() (*Client, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}

	return &Client{
		c: c,
	}, nil
}

// Close releases resources used by a Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Interfaces returns a list of the system's WiFi network interfaces.
func (c *Client) Interfaces() ([]*Interface, error) {
	return c.c.Interfaces()
}

// BSS retrieves the BSS associated with a WiFi interface.
func (c *Client) BSS(ifi *Interface) (*BSS, error) {
	return c.c.BSS(ifi)
}

// StationInfo retrieves all station statistics about a WiFi interface.
func (c *Client) StationInfo(ifi *Interface) ([]*StationInfo, error) {
	return c.c.StationInfo(ifi)
}

// PHY returns the WiFi device corresponding to the specified index.
func (c *Client) PHY(index int) (*PHY, error) {
	return c.c.PHY(index)
}

// PHYs returns a list of the system's WiFi devices.
func (c *Client) PHYs() ([]*PHY, error) {
	return c.c.PHYs()
}

// An osClient is the operating system-specific implementation of Client.
type osClient interface {
	Close() error
	Interfaces() ([]*Interface, error)
	BSS(ifi *Interface) (*BSS, error)
	PHY(n int) (*PHY, error)
	PHYs() ([]*PHY, error)
	StationInfo(ifi *Interface) ([]*StationInfo, error)
}
