package wifi

import (
	"fmt"
	"runtime"
	"time"
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

// Connect starts connecting the interface to the specified ssid.
func (c *Client) Connect(ifi *Interface, ssid string) error {
	return c.c.Connect(ifi, ssid)
}

// SetType sets the interface type.
func (c *Client) SetType(ifi *Interface, ifType InterfaceType) error {
	return c.c.SetType(ifi, ifType)
}

// JoinIBSSExt joins the interface to the specified IBSS (ad-hoc) network with the specified parameters.
func (c *Client) JoinIBSS(ifi *Interface, ssid string, frequencyMHz int, chanWidth ChanWidth, beaconInterval time.Duration, basicRate, mCastRate int) error {
	return c.c.JoinIBSS(ifi, ssid, frequencyMHz, chanWidth, beaconInterval, basicRate, mCastRate)
}

// LeaveIBSS makes the interface leave the IBSS (ad-hoc) network.
func (c *Client) LeaveIBSS(ifi *Interface) error {
	return c.c.LeaveIBSS(ifi)
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

// An osClient is the operating system-specific implementation of Client.
type osClient interface {
	Close() error
	Interfaces() ([]*Interface, error)
	BSS(ifi *Interface) (*BSS, error)
	StationInfo(ifi *Interface) ([]*StationInfo, error)
	Connect(ifi *Interface, ssid string) error
	SetType(ifi *Interface, ifType InterfaceType) error
	JoinIBSS(ifi *Interface, ssid string, frequencyMHz int, chanWidth ChanWidth, beaconInterval time.Duration, basicRate, mCastRate int) error
	LeaveIBSS(ifi *Interface) error
}
