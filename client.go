package wifi

import (
	"context"
	"time"
)

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

// BSS retrieves the BSS associated with a WiFi interface.
func (c *Client) BSS(ifi *Interface) (*BSS, error) {
	return c.c.BSS(ifi)
}

// PHYs returns a list of the system's WiFi devices.
func (c *Client) PHYs() ([]*PHY, error) { return c.c.PHYs() }

// AccessPoints retrieves the currently known BSS around the specified Interface.
func (c *Client) AccessPoints(ifi *Interface) ([]*BSS, error) {
	return c.c.AccessPoints(ifi)
}

// Scan requests the wifi interface to scan for new access points.
//
// Use context.WithDeadline to set a timeout.
func (c *Client) Scan(ctx context.Context, ifi *Interface) error {
	return c.c.Scan(ctx, ifi)
}

// StationInfo retrieves all station statistics about a WiFi interface.
//
// Since v0.2.0: if there are no stations, an empty slice is returned instead
// of an error.
func (c *Client) StationInfo(ifi *Interface) ([]*StationInfo, error) {
	return c.c.StationInfo(ifi)
}

// SurveyInfo retrieves the survey information about a WiFi interface.
func (c *Client) SurveyInfo(ifi *Interface) ([]*SurveyInfo, error) { return c.c.SurveyInfo(ifi) }

// SetDeadline sets the read and write deadlines associated with the connection.
func (c *Client) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

// SetReadDeadline sets the read deadline associated with the connection.
func (c *Client) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline associated with the connection.
func (c *Client) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

// ReloadRegulatoryDatabase reloads the wireless regulatory database.
//
// This can be used if cfg80211 was built into the kernel and the wireless regulatory database
// was not available during early boot.
//
// See https://wireless.docs.kernel.org/en/latest/en/developers/regulatory/wireless-regdb.html
func (c *Client) ReloadRegulatoryDatabase() error {
	return c.c.ReloadRegulatoryDatabase()
}

// GetRegulatoryRegion gets the system-wide regulatory domain.
// See https://wireless.docs.kernel.org/en/latest/en/developers/regulatory/wireless-regdb.html
func (c *Client) GetRegulatoryDomain() (*RegulatoryDomain, error) {
	return c.c.GetRegulatoryDomain()
}

// SetRegulatoryRegion sets the system-wide regulatory region used by all nl80211 devices.
// You may need to call [Client.ReloadRegulatoryDatabase] first to ensure the region is updated correctly.
//
// region must be an ISO 3166-1 alpha-2 country code (e.g. "GB" or "US").
// hint should almost always be [RegulatoryHintUser].
//
// See https://wireless.docs.kernel.org/en/latest/en/developers/regulatory/wireless-regdb.html
func (c *Client) SetRegulatoryRegion(region string, hint RegulatoryHint) error {
	return c.c.SetRegulatoryRegion(region, hint)
}
