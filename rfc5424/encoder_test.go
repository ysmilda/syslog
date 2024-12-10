//nolint:lll
package rfc5424

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEncoder(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    Message
		expected string
	}{
		{
			name: "valid message - example 1",
			input: Message{
				PRI:       PRI{value: 34},
				Version:   1,
				Timestamp: time.Date(2003, 10, 11, 22, 14, 15, 3000000, time.UTC),
				Hostname:  "mymachine.example.com",
				AppName:   "su",
				MsgID:     "ID47",
				Message:   "'su root' failed for lonvick on /dev/pts/8'",
			},
			expected: "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8'",
		},
		{
			name: "valid message - example 2",
			input: Message{
				PRI:       PRI{value: 165},
				Version:   1,
				Timestamp: time.Date(2003, 8, 24, 5, 14, 15, 3000, time.FixedZone("", -7*60*60)),
				Hostname:  "192.0.2.1",
				AppName:   "myproc",
				ProcID:    "8710",
				Message:   "%% It's time to make the do-nuts.",
			},
			expected: "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.",
		},
		{
			name: "valid message - example 3",
			input: Message{
				PRI:       PRI{value: 165},
				Version:   1,
				Timestamp: time.Date(2003, 10, 11, 22, 14, 15, 3000000, time.UTC),
				Hostname:  "mymachine.example.com",
				AppName:   "evntslog",
				MsgID:     "ID47",
				StructuredData: []StructuredDataElement{
					{
						ID: "exampleSDID@32473",
						Parameters: map[string]string{
							"iut": "3", // Limited to one entry because of unorderedness of maps
						},
					},
				},
				Message: "An application event log entry...",
			},
			expected: "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] An application event log entry...",
		},
		{
			name: "valid message - example 4",
			input: Message{
				PRI:       PRI{value: 165},
				Version:   1,
				Timestamp: time.Date(2003, 10, 11, 22, 14, 15, 3000000, time.UTC),
				Hostname:  "mymachine.example.com",
				AppName:   "evntslog",
				MsgID:     "ID47",
				StructuredData: []StructuredDataElement{
					{
						ID: "exampleSDID@32473",
						Parameters: map[string]string{
							"eventSource": "Application", // Limited to one entry because of unorderedness of maps
						},
					},
					{
						ID: "examplePriority@32473",
						Parameters: map[string]string{
							"class": "high", // Limited to one entry because of unorderedness of maps
						},
					},
				},
			},
			expected: "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 eventSource=\"Application\"][examplePriority@32473 class=\"high\"]",
		},
	}

	for _, tc := range testcases {
		var buf bytes.Buffer
		_, err := NewEncoder(&buf).Encode(tc.input)
		assert.Nil(t, err, err, tc.name)
		assert.Equal(t, tc.expected, buf.String(), tc.name)
	}
}
