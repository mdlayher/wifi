//go:build !linux
// +build !linux

package wifi

var _ osClient = &client{}

// A conn is the no-op implementation of a netlink sockets connection.
type client struct{}

func newClient() (*client, error) { return nil, errUnimplemented }

func (*client) Close() error                                     { return errUnimplemented }
func (*client) Interfaces() ([]*Interface, error)                { return nil, errUnimplemented }
func (*client) BSS(_ *Interface) (*BSS, error)                   { return nil, errUnimplemented }
func (*client) StationInfo(_ *Interface) ([]*StationInfo, error) { return nil, errUnimplemented }
func (*client) Connect(_ *Interface, _ string) error             { return errUnimplemented }
func (*client) ConnectWPAPSK(_ *Interface, _, _ string) error    { return errUnimplemented }
