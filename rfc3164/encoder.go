package rfc3164

import (
	"fmt"
	"io"
	"time"
)

type Encoder struct {
	w io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

func (enc Encoder) Encode(msg Message) (int, error) {
	return fmt.Fprintf(enc.w,
		"<%d>%s %s %s%s",
		// PRI
		msg.PRI.value,
		// HEADER
		msg.Timestamp.Format(time.Stamp), msg.Hostname,
		// MSG
		msg.Tag, msg.Content,
	)
}
