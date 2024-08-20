package rfc5424

import "time"

type Message struct {
	PRI                    PRI
	Version                byte
	Timestamp              time.Time
	Hostname               string
	AppName                string
	ProcID                 string
	MsgID                  string
	StructuredData         string
	StructuredDataElements *[]StructuredDataElements
	Message                string
}

type PRI struct {
	value byte
}

func (p PRI) Facility() byte {
	return p.value & 0xF8 >> 3
}

func (p PRI) Severity() byte {
	return p.value & 0x07
}

type StructuredDataElements struct {
	ID         string
	Parameters map[string]string
}
