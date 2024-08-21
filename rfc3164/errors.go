package rfc3164

import "errors"

var (
	ErrInvalidPRI       = errors.New("invalid PRI")
	ErrInvalidTimestamp = errors.New("invalid timestamp")
	ErrInvalidHostname  = errors.New("invalid hostname")
)
