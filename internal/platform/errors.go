package platform

import "errors"

var ErrNotSupported = errors.New("packet io not supported on this platform")
