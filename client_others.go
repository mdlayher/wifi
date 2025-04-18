//go:build !linux
// +build !linux

package wifi

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

// errUnimplemented is returned by all functions on platforms that
// do not have package wifi implemented.
var errUnimplemented = fmt.Errorf("wifi: not implemented on %s", runtime.GOOS)

// A conn is the no-op implementation of a netlink sockets connection.
type client struct{}

func newClient() (*client, error) { return nil, errUnimplemented }

func (*client) Close() error                                     { return errUnimplemented }
func (*client) Interfaces() ([]*Interface, error)                { return nil, errUnimplemented }
func (*client) BSS(_ *Interface) (*BSS, error)                   { return nil, errUnimplemented }
func (client) AccessPoints(ifi *Interface) ([]*BSS, error)       { return nil, errUnimplemented }
func (*client) StationInfo(_ *Interface) ([]*StationInfo, error) { return nil, errUnimplemented }
func (*client) SurveyInfo(_ *Interface) ([]*SurveyInfo, error)   { return nil, errUnimplemented }
func (*client) Scan(ctx context.Context, ifi *Interface) error   { return errUnimplemented }
func (*client) Connect(_ *Interface, _ string) error             { return errUnimplemented }
func (*client) Disconnect(_ *Interface) error                    { return errUnimplemented }
func (*client) ConnectWPAPSK(_ *Interface, _, _ string) error    { return errUnimplemented }
func (*client) SetDeadline(t time.Time) error                    { return errUnimplemented }
func (*client) SetReadDeadline(t time.Time) error                { return errUnimplemented }
func (*client) SetWriteDeadline(t time.Time) error               { return errUnimplemented }
