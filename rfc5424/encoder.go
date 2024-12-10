package rfc5424

import (
	"fmt"
	"io"
	"strings"
	"time"
)

type Encoder struct {
	w io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

func (enc Encoder) Encode(msg Message) (int, error) {
	if msg.Version < 1 || msg.Version > 99 {
		return 0, ErrInvalidVersion
	}

	t := time.Time{}
	timestamp := "-"
	if t != msg.Timestamp {
		timestamp = msg.Timestamp.Format(time.RFC3339Nano)
	}

	if len(msg.Hostname) > 255 {
		return 0, ErrInvalidHostname
	}
	hostname := "-"
	if len(msg.Hostname) > 0 {
		hostname = msg.Hostname
	}

	if len(msg.AppName) > 48 {
		return 0, ErrInvalidAppName
	}
	appname := "-"
	if len(msg.AppName) > 0 {
		appname = msg.AppName
	}

	if len(msg.ProcID) > 128 {
		return 0, ErrInvalidProcID
	}
	procid := "-"
	if len(msg.ProcID) > 0 {
		procid = msg.ProcID
	}

	if len(msg.MsgID) > 32 {
		return 0, ErrInvalidMsgID
	}
	msgid := "-"
	if len(msg.MsgID) > 0 {
		msgid = msg.MsgID
	}

	structuredData := "-"
	if msg.StructuredData != nil {
		structuredData = ""
		for _, element := range msg.StructuredData {
			b := strings.Builder{}
			for id, parameter := range element.Parameters {
				if b.Len() != 0 {
					b.WriteString(" ")
				}
				b.WriteString(id)
				b.WriteString("=\"")
				b.WriteString(parameter)
				b.WriteString("\"")

			}
			structuredData += fmt.Sprintf("[%s %s]", element.ID, b.String())
		}
	}

	message := ""
	if msg.Message != "" {
		message = " " + msg.Message
	}

	return fmt.Fprintf(
		enc.w,
		"<%d>%d %s %s %s %s %s %s%s",
		// HEADER
		msg.PRI.value, msg.Version, timestamp, hostname, appname, procid, msgid,
		// STRUCTURED DATA
		structuredData,
		// MESSAGE
		message,
	)
}
