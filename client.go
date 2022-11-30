package wifi

import "fmt"

// A Client is a type which can access WiFi device actions and statistics
// using operating system-specific operations.
type Client struct {
	c *client
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

// Dissconnect disconnects the interface.
func (c *Client) Disconnect(ifi *Interface) error {
	return c.c.Disconnect(ifi)
}

// Connect starts connecting the interface to the specified ssid using WPA.
func (c *Client) ConnectWPAPSK(ifi *Interface, ssid, psk string) error {
	return c.c.ConnectWPAPSK(ifi, ssid, psk)
}

// Interfaces returns a list of the system's WiFi network interfaces.
func (c *Client) Interfaces() ([]*Interface, error) {
	return c.c.Interfaces()
}

// InterfaceByName calls Interfaces() and returns one interface or nil 
// if the requested interface doesn't exist.
func (c *Client) InterfaceByName(name string) (*Interface, error) {
	return c.c.InterfaceByName(name)
}

// BSS retrieves the BSS associated with a WiFi interface.
func (c *Client) BSS(ifi *Interface) (*BSS, error) {
	return c.c.BSS(ifi)
}

// StationInfo retrieves all station statistics about a WiFi interface.
func (c *Client) StationInfo(ifi *Interface) ([]*StationInfo, error) {
	return c.c.StationInfo(ifi)
}

// SetFrequency sets the frequency of a wireless interface.
func (c *Client) SetFrequency(ifi *Interface, freq int) error {
	return c.c.SetFrequency(ifi, freq)
}

//SetModeMonitor sets a wireless interface iftype to MONITOR.
func (c *Client) SetModeMonitor(ifi *Interface) error {
	fmt.Printf("Setting monitor mode on interface %v\n", ifi)
	return c.c.SetModeMonitor(ifi)
}

//SetModeStation sets a wireless interface iftype to Station.
func (c *Client) SetModeStation(ifi *Interface) error {
	return c.c.SetModeStation(ifi)
}