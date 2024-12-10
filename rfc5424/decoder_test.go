//nolint:lll
package rfc5424

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDecode(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected *Message
	}{
		{
			name:  "valid message - example 1",
			input: []byte("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8'"),
			expected: &Message{
				PRI:       PRI{value: 34},
				Version:   1,
				Timestamp: time.Date(2003, 10, 11, 22, 14, 15, 3000000, time.UTC),
				Hostname:  "mymachine.example.com",
				AppName:   "su",
				MsgID:     "ID47",
				Message:   "'su root' failed for lonvick on /dev/pts/8'",
			},
		},
		{
			name:  "valid message - example 2",
			input: []byte("<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts."),
			expected: &Message{
				PRI:       PRI{value: 165},
				Version:   1,
				Timestamp: time.Date(2003, 8, 24, 5, 14, 15, 3000, time.FixedZone("", -7*60*60)),
				Hostname:  "192.0.2.1",
				AppName:   "myproc",
				ProcID:    "8710",
				Message:   "%% It's time to make the do-nuts.",
			},
		},
		{
			name:  "valid message - example 3",
			input: []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] An application event log entry..."),
			expected: &Message{
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
							"iut":         "3",
							"eventSource": "Application",
							"eventID":     "1011",
						},
					},
				},
				Message: "An application event log entry...",
			},
		},
		{
			name:  "valid message - example 4",
			input: []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]"),
			expected: &Message{
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
							"iut":         "3",
							"eventSource": "Application",
							"eventID":     "1011",
						},
					},
					{
						ID: "examplePriority@32473",
						Parameters: map[string]string{
							"class": "high",
						},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		msg, err := NewDecoder(bytes.NewReader(tc.input)).Decode()
		assert.Nil(t, err)
		assert.Equal(t, tc.expected, msg, tc.name)
	}
}

func TestParsePRI(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected byte
		err      error
	}{
		{
			name:     "valid PRI - single digit",
			input:    []byte("<3>"),
			expected: 3,
		},
		{
			name:     "valid PRI - double digit",
			input:    []byte("<34>"),
			expected: 34,
		},
		{
			name:     "valid PRI - triple digit",
			input:    []byte("<165>"),
			expected: 165,
		},
		{
			name:     "invalid PRI - missing closing bracket",
			input:    []byte("<165"),
			expected: 0,
			err:      ErrInvalidPRI,
		},
		{
			name:     "invalid PRI - invalid character",
			input:    []byte("<1a5>"),
			expected: 0,
			err:      ErrInvalidPRI,
		},
		{
			name:     "invalid PRI - value too high",
			input:    []byte("<192>"),
			expected: 0,
			err:      ErrInvalidPRI,
		},
		{
			name:     "invalid PRI - value too long",
			input:    []byte("<0192>"),
			expected: 0,
			err:      ErrInvalidPRI,
		},
		{
			name:     "invalid PRI - missing opening bracket",
			input:    []byte("165>"),
			expected: 0,
			err:      ErrInvalidPRI,
		},
		{
			name:     "invalid PRI - empty",
			input:    []byte(""),
			expected: 0,
			err:      ErrInvalidPRI,
		},
	}

	for _, tc := range testcases {
		pri, err := decodePRI(bytes.NewReader(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, pri, tc.name)
	}
}

func TestParseVersion(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected byte
		err      error
	}{
		{
			name:     "valid version - single digit",
			input:    []byte("1 "),
			expected: 1,
		},
		{
			name:     "invalid version - zero value",
			input:    []byte("0 "),
			expected: 0,
			err:      ErrInvalidVersion,
		},
		{
			name:     "invalid version - double digit",
			input:    []byte("12 "),
			expected: 0,
			err:      ErrInvalidVersion,
		},
		{
			name:     "invalid version - non-digit",
			input:    []byte("a "),
			expected: 0,
			err:      ErrInvalidVersion,
		},
		{
			name:     "invalid version - empty",
			input:    []byte(""),
			expected: 0,
			err:      ErrInvalidVersion,
		},
	}

	for _, tc := range testcases {
		version, err := decodeVersion(bytes.NewReader(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, version, tc.name)
	}
}

func TestParseTimestamp(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected time.Time
		err      error
	}{
		{
			name:     "invalid timestamp - empty",
			input:    []byte(""),
			expected: time.Time{},
			err:      ErrInvalidTimestamp,
		},
		{
			name:     "invalid timestamp - no space",
			input:    []byte("1985-04-12T23:20:50.52Z"),
			expected: time.Time{},
			err:      ErrInvalidTimestamp,
		},
		{
			name:     "valid timestamp - nil",
			input:    []byte("- "),
			expected: time.Time{},
		},
		{
			name:     "valid timestamp - example 1",
			input:    []byte("1985-04-12T23:20:50.52Z "),
			expected: time.Date(1985, 4, 12, 23, 20, 50, 520000000, time.UTC),
		},
		{
			name:     "valid timestamp - example 2",
			input:    []byte("1985-04-12T19:20:50.52-04:00 "),
			expected: time.Date(1985, 4, 12, 19, 20, 50, 520000000, time.FixedZone("", -4*60*60)),
		},
		{
			name:     "valid timestamp - example 3",
			input:    []byte("2003-10-11T22:14:15.003Z "),
			expected: time.Date(2003, 10, 11, 22, 14, 15, 3000000, time.UTC),
		},
		{
			name:     "valid timestamp - example 4",
			input:    []byte("2003-08-24T05:14:15.000003-07:00 "),
			expected: time.Date(2003, 8, 24, 5, 14, 15, 3000, time.FixedZone("", -7*60*60)),
		},
		{
			name:     "invalid timestamp - example 5",
			input:    []byte("2003-08-24T05:14:15.000000003-07:00"),
			expected: time.Time{},
			err:      ErrInvalidTimestamp,
		},
	}

	for _, tc := range testcases {
		timestamp, err := decodeTimestamp(bytes.NewReader(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, timestamp, tc.name)
	}
}

func TestParseHostname(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected string
		err      error
	}{
		{
			name:     "valid hostname - nil",
			input:    []byte("- "),
			expected: "",
		},
		{
			name:     "valid hostname",
			input:    []byte("mymachine.example.com "),
			expected: "mymachine.example.com",
		},
		{
			name:     "invalid hostname - empty",
			input:    []byte(""),
			expected: "",
			err:      ErrInvalidHostname,
		},
		{
			name:     "invalid hostname - too long",
			input:    []byte(strings.Repeat("a", 256) + " "),
			expected: "",
			err:      ErrInvalidHostname,
		},
	}

	for _, tc := range testcases {
		hostname, err := decodeHostname(bytes.NewReader(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, hostname, tc.name)
	}
}

func TestParseAppName(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected string
		err      error
	}{
		{
			name:     "valid app-name - nil",
			input:    []byte("- "),
			expected: "",
		},
		{
			name:     "valid app-name",
			input:    []byte("su "),
			expected: "su",
		},
		{
			name:     "invalid app-name - empty",
			input:    []byte(""),
			expected: "",
			err:      ErrInvalidAppName,
		},
		{
			name:     "invalid app-name - too long",
			input:    []byte(strings.Repeat("a", 49) + " "),
			expected: "",
			err:      ErrInvalidAppName,
		},
	}

	for _, tc := range testcases {
		appName, err := decodeAppName(bytes.NewReader(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, appName, tc.name)
	}
}

func TestParseProcID(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected string
		err      error
	}{
		{
			name:     "valid proc-id - nil",
			input:    []byte("- "),
			expected: "",
		},
		{
			name:     "valid proc-id",
			input:    []byte("ID47 "),
			expected: "ID47",
		},
		{
			name:     "invalid proc-id - empty",
			input:    []byte(""),
			expected: "",
			err:      ErrInvalidProcID,
		},
		{
			name:     "invalid proc-id - too long",
			input:    []byte(strings.Repeat("a", 129) + " "),
			expected: "",
			err:      ErrInvalidProcID,
		},
	}

	for _, tc := range testcases {
		procID, err := decodeProcID(bytes.NewReader(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, procID, tc.name)
	}
}

func TestParseMsgID(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected string
		err      error
	}{
		{
			name:     "valid msg-id - nil",
			input:    []byte("- "),
			expected: "",
		},
		{
			name:     "valid msg-id",
			input:    []byte("ID47 "),
			expected: "ID47",
		},
		{
			name:     "invalid msg-id - empty",
			input:    []byte(""),
			expected: "",
			err:      ErrInvalidMsgID,
		},
		{
			name:     "invalid msg-id - too long",
			input:    []byte(strings.Repeat("a", 33) + " "),
			expected: "",
			err:      ErrInvalidMsgID,
		},
	}

	for _, tc := range testcases {
		msgID, err := decodeMsgID(bytes.NewReader(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, msgID, tc.name)
	}
}

func TestParseStructuredData(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected string
		err      error
	}{
		{
			name:     "valid structured-data - nil",
			input:    []byte("- "),
			expected: "",
		},
		{
			name:     "valid structured-data - example 1",
			input:    []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] "),
			expected: "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]",
		},
		{
			name:     "valid structured-data - example 2",
			input:    []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] "),
			expected: "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]",
		},
		{
			name:     "valid structured-data - no space",
			input:    []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]"),
			expected: "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]",
		},
		{
			name:     "invalid structured-data - empty",
			input:    []byte(""),
			expected: "",
			err:      ErrInvalidStructuredData,
		},
		{
			name:     "invalid structured-data - missing closing bracket",
			input:    []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011 "),
			expected: "",
			err:      ErrInvalidStructuredData,
		},
	}

	for _, tc := range testcases {
		sd, err := decodeStructuredData(bytes.NewReader(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, sd, tc.name)
	}
}

func TestParseStructuredDataElements(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected []StructuredDataElement
		err      error
	}{
		{
			name:     "valid structured-data-elements - empty",
			input:    []byte(""),
			expected: nil,
		},
		{
			name:  "valid structured-data-elements - example 1",
			input: []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] "),
			expected: []StructuredDataElement{
				{
					ID: "exampleSDID@32473",
					Parameters: map[string]string{
						"iut":         "3",
						"eventSource": "Application",
						"eventID":     "1011",
					},
				},
			},
		},
		{
			name:  "valid structured-data-elements - example 2",
			input: []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] "),
			expected: []StructuredDataElement{
				{
					ID: "exampleSDID@32473",
					Parameters: map[string]string{
						"iut":         "3",
						"eventSource": "Application",
						"eventID":     "1011",
					},
				},
				{
					ID: "examplePriority@32473",
					Parameters: map[string]string{
						"class": "high",
					},
				},
			},
		},
		{
			name:     "invalid structured-data-elements - missing ID",
			input:    []byte("[ iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] "),
			expected: nil,
			err:      ErrInvalidStructuredData,
		},
		{
			name:     "invalid structured-data-elements - invalid parameter",
			input:    []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\" invalid] "),
			expected: nil,
			err:      ErrInvalidStructuredData,
		},
	}

	for _, tc := range testcases {
		sd, err := decodeStructuredDataElements(string(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, sd, tc.name)
	}
}

func TestParseString(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		length   int
		expected string
		err      error
	}{
		{
			name:     "valid string",
			input:    []byte("test "),
			length:   4,
			expected: "test",
		},
		{
			name:     "valid string - nil",
			input:    []byte("- "),
			length:   0,
			expected: "",
		},
		{
			name:     "invalid string - empty",
			input:    []byte(""),
			length:   0,
			expected: "",
			err:      ErrInvalidMessage,
		},
		{
			name:     "invalid string - too long",
			input:    []byte("test "),
			length:   3,
			expected: "",
			err:      ErrInvalidMessage,
		},
		{
			name:     "invalid string - no space",
			input:    []byte("test"),
			length:   0,
			expected: "",
			err:      ErrInvalidMessage,
		},
	}

	for _, tc := range testcases {
		str, err := decodeString(bytes.NewReader(tc.input), tc.length, ErrInvalidMessage)
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, str, tc.name)
	}
}

func TestCheckNilValue(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		input    []byte
		expected bool
		err      error
	}{
		{
			name:     "nil value",
			input:    []byte("- "),
			expected: true,
		},
		{
			name:     "nil value with invalid character",
			input:    []byte("-a "),
			expected: false,
			err:      ErrInvalidNilValue,
		},
		{
			name:     "non-nil value",
			input:    []byte("test "),
			expected: false,
		},
		{
			name:     "empty value",
			input:    []byte(""),
			expected: false,
			err:      ErrInvalidNilValue,
		},
	}

	for _, tc := range testcases {
		isNil, err := checkNilValue(bytes.NewReader(tc.input))
		assert.Equal(t, tc.err, err, tc.name)
		assert.Equal(t, tc.expected, isNil, tc.name)
	}
}

func BenchmarkParse(b *testing.B) {
	msg := []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] An application event log entry...")
	for i := 0; i < b.N; i++ {
		_, err := NewDecoder(bytes.NewReader(msg)).Decode()
		if err != nil {
			b.Fatal(err)
		}
	}
}
