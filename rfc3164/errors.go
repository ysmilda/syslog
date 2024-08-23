package rfc3164

import "errors"

var (
	ErrMessageIgnored   = errors.New("message ignored")
	ErrInvalidPRI       = errors.New("invalid PRI")
	ErrInvalidTimestamp = errors.New("invalid timestamp")
	ErrInvalidHostname  = errors.New("invalid hostname")
)
