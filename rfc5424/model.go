package rfc5424

import "time"

// Message represents a syslog message as defined in RFC 5424.
type Message struct {
	PRI            PRI
	Version        byte
	Timestamp      time.Time
	Hostname       string
	AppName        string
	ProcID         string
	MsgID          string
	StructuredData []StructuredDataElement
	Message        string
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

type Facility byte

// Definition taken from https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1
const (
	FacilityKernel Facility = iota
	FacilityUser
	FacilityMail
	FacilitySystem
	FacilityAuth
	FacilitySyslog
	FacilityLPR
	FacilityNews
	FacilityUUCP
	FacilityClock
	FacilityAuth2
	FacilityFTP
	FacilityNTP
	FacilityLogAudit
	FacilityLogAlert
	FacilityClock2
	FacilityLocal0
	FacilityLocal1
	FacilityLocal2
	FacilityLocal3
	FacilityLocal4
	FacilityLocal5
	FacilityLocal6
	FacilityLocal7
)

// Facility returns the facility value of the PRI.
func (p PRI) Facility() Facility {
	return Facility(p.value & 0xF8 >> 3)
}

type Severity byte

// Definition taken from https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1
const (
	SeverityEmergency Severity = iota
	SeverityAlert
	SeverityCritical
	SeverityError
	SeverityWarning
	SeverityNotice
	SeverityInformational
	SeverityDebug
)

// Severity returns the severity value of the PRI.
func (p PRI) Severity() Severity {
	return Severity(p.value & 0x07)
}

// StructuredDataElement represents a structured data element in a syslog message.
type StructuredDataElement struct {
	ID         string
	Parameters map[string]string
}
