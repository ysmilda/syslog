package rfc5424

import "time"

// Message represents a syslog message as defined in RFC 5424.
type Message struct {
	PRI                    PRI
	Version                byte
	Timestamp              time.Time
	Hostname               string
	AppName                string
	ProcID                 string
	MsgID                  string
	StructuredData         string
	StructuredDataElements *[]StructuredDataElement
	Message                string
}

// PRI represents the Priority value of a syslog message.
// The PRI is a single byte that encodes the facility and severity of the message.
type PRI struct {
	value byte
}

func NewPRI(value byte) (PRI, error) {
	if value > 191 {
		return PRI{}, ErrInvalidPRI
	}
	return PRI{value: value}, nil
}

// Facility returns the facility value of the PRI.
func (p PRI) Facility() byte {
	return p.value & 0xF8 >> 3
}

// Severity returns the severity value of the PRI.
func (p PRI) Severity() byte {
	return p.value & 0x07
}

// StructuredDataElement represents a structured data element in a syslog message.
type StructuredDataElement struct {
	ID         string
	Parameters map[string]string
}
