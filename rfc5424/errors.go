package rfc5424

import "errors"

var (
	ErrMessageIgnored        = errors.New("message ignored")
	ErrInvalidNilValue       = errors.New("invalid nil value")
	ErrInvalidPRI            = errors.New("invalid PRI")
	ErrInvalidVersion        = errors.New("invalid version")
	ErrInvalidTimestamp      = errors.New("invalid timestamp")
	ErrInvalidHostname       = errors.New("invalid hostname")
	ErrInvalidAppName        = errors.New("invalid app-name")
	ErrInvalidProcID         = errors.New("invalid proc-id")
	ErrInvalidMsgID          = errors.New("invalid msg-id")
	ErrInvalidStructuredData = errors.New("invalid structured-data")
	ErrInvalidMessage        = errors.New("invalid message")
)
