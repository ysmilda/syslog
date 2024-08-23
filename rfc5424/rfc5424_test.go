//nolint:lll
package rfc5424

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name            string
		msg             []byte
		expectedMessage Message
		expectedError   error
	}{
		{
			name: "valid message - example 1",
			msg:  []byte("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8'"),
			expectedMessage: Message{
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
			name: "valid message - example 2",
			msg:  []byte("<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts."),
			expectedMessage: Message{
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
			name: "valid message - example 3",
			msg:  []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] An application event log entry..."),
			expectedMessage: Message{
				PRI:            PRI{value: 165},
				Version:        1,
				Timestamp:      time.Date(2003, 10, 11, 22, 14, 15, 3000000, time.UTC),
				Hostname:       "mymachine.example.com",
				AppName:        "evntslog",
				MsgID:          "ID47",
				StructuredData: "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]",
				Message:        "An application event log entry...",
			},
		},
		{
			name: "valid message - example 4",
			msg:  []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]"),
			expectedMessage: Message{
				PRI:            PRI{value: 165},
				Version:        1,
				Timestamp:      time.Date(2003, 10, 11, 22, 14, 15, 3000000, time.UTC),
				Hostname:       "mymachine.example.com",
				AppName:        "evntslog",
				MsgID:          "ID47",
				StructuredData: "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]",
			},
		},
	}

	p := NewParser()

	for _, tc := range testcases {
		msg, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedMessage, msg, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParsePRI(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedPRI   byte
		expectedError error
	}{
		{
			name:        "valid PRI - single digit",
			msg:         []byte("<3>"),
			expectedPRI: 3,
		},
		{
			name:        "valid PRI - double digit",
			msg:         []byte("<34>"),
			expectedPRI: 34,
		},
		{
			name:        "valid PRI - triple digit",
			msg:         []byte("<165>"),
			expectedPRI: 165,
		},
		{
			name:          "invalid PRI - missing closing bracket",
			msg:           []byte("<165"),
			expectedPRI:   0,
			expectedError: ErrInvalidPRI,
		},
		{
			name:          "invalid PRI - invalid character",
			msg:           []byte("<1a5>"),
			expectedPRI:   0,
			expectedError: ErrInvalidPRI,
		},
		{
			name:          "invalid PRI - value too high",
			msg:           []byte("<192>"),
			expectedPRI:   0,
			expectedError: ErrInvalidPRI,
		},
		{
			name:          "invalid PRI - value too long",
			msg:           []byte("<0192>"),
			expectedPRI:   0,
			expectedError: ErrInvalidPRI,
		},
		{
			name:          "invalid PRI - missing opening bracket",
			msg:           []byte("165>"),
			expectedPRI:   0,
			expectedError: ErrInvalidPRI,
		},
		{
			name:          "invalid PRI - empty",
			msg:           []byte(""),
			expectedPRI:   0,
			expectedError: ErrInvalidPRI,
		},
	}

	for _, tc := range testcases {
		pri, err := parsePRI(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedPRI, pri, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParseVersion(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name            string
		msg             []byte
		expectedVersion byte
		expectedError   error
	}{
		{
			name:            "valid version - single digit",
			msg:             []byte("1 "),
			expectedVersion: 1,
		},
		{
			name:            "invalid version - zero value",
			msg:             []byte("0 "),
			expectedVersion: 0,
			expectedError:   ErrInvalidVersion,
		},
		{
			name:            "invalid version - double digit",
			msg:             []byte("12 "),
			expectedVersion: 0,
			expectedError:   ErrInvalidVersion,
		},
		{
			name:            "invalid version - non-digit",
			msg:             []byte("a "),
			expectedVersion: 0,
			expectedError:   ErrInvalidVersion,
		},
		{
			name:            "invalid version - empty",
			msg:             []byte(""),
			expectedVersion: 0,
			expectedError:   ErrInvalidVersion,
		},
	}

	for _, tc := range testcases {
		version, err := parseVersion(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedVersion, version, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParseTimestamp(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedTime  time.Time
		expectedError error
	}{
		{
			name:          "invalid timestamp - empty",
			msg:           []byte(""),
			expectedTime:  time.Time{},
			expectedError: ErrInvalidTimestamp,
		},
		{
			name:          "invalid timestamp - no space",
			msg:           []byte("1985-04-12T23:20:50.52Z"),
			expectedTime:  time.Time{},
			expectedError: ErrInvalidTimestamp,
		},
		{
			name:         "valid timestamp - nil",
			msg:          []byte("- "),
			expectedTime: time.Time{},
		},
		{
			name:         "valid timestamp - example 1",
			msg:          []byte("1985-04-12T23:20:50.52Z "),
			expectedTime: time.Date(1985, 4, 12, 23, 20, 50, 520000000, time.UTC),
		},
		{
			name:         "valid timestamp - example 2",
			msg:          []byte("1985-04-12T19:20:50.52-04:00 "),
			expectedTime: time.Date(1985, 4, 12, 19, 20, 50, 520000000, time.FixedZone("", -4*60*60)),
		},
		{
			name:         "valid timestamp - example 3",
			msg:          []byte("2003-10-11T22:14:15.003Z "),
			expectedTime: time.Date(2003, 10, 11, 22, 14, 15, 3000000, time.UTC),
		},
		{
			name:         "valid timestamp - example 4",
			msg:          []byte("2003-08-24T05:14:15.000003-07:00 "),
			expectedTime: time.Date(2003, 8, 24, 5, 14, 15, 3000, time.FixedZone("", -7*60*60)),
		},
		{
			name:          "invalid timestamp - example 5",
			msg:           []byte("2003-08-24T05:14:15.000000003-07:00"),
			expectedTime:  time.Time{},
			expectedError: ErrInvalidTimestamp,
		},
	}

	for _, tc := range testcases {
		timestamp, err := parseTimestamp(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedTime, timestamp, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParseHostname(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedHost  string
		expectedError error
	}{
		{
			name:         "valid hostname - nil",
			msg:          []byte("- "),
			expectedHost: "",
		},
		{
			name:         "valid hostname",
			msg:          []byte("mymachine.example.com "),
			expectedHost: "mymachine.example.com",
		},
		{
			name:          "invalid hostname - empty",
			msg:           []byte(""),
			expectedHost:  "",
			expectedError: ErrInvalidHostname,
		},
		{
			name:          "invalid hostname - too long",
			msg:           []byte(strings.Repeat("a", 256) + " "),
			expectedHost:  "",
			expectedError: ErrInvalidHostname,
		},
	}

	for _, tc := range testcases {
		hostname, err := parseHostname(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedHost, hostname, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParseAppName(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedApp   string
		expectedError error
	}{
		{
			name:        "valid app-name - nil",
			msg:         []byte("- "),
			expectedApp: "",
		},
		{
			name:        "valid app-name",
			msg:         []byte("su "),
			expectedApp: "su",
		},
		{
			name:          "invalid app-name - empty",
			msg:           []byte(""),
			expectedApp:   "",
			expectedError: ErrInvalidAppName,
		},
		{
			name:          "invalid app-name - too long",
			msg:           []byte(strings.Repeat("a", 49) + " "),
			expectedApp:   "",
			expectedError: ErrInvalidAppName,
		},
	}

	for _, tc := range testcases {
		appName, err := parseAppName(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedApp, appName, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParseProcID(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedProc  string
		expectedError error
	}{
		{
			name:         "valid proc-id - nil",
			msg:          []byte("- "),
			expectedProc: "",
		},
		{
			name:         "valid proc-id",
			msg:          []byte("ID47 "),
			expectedProc: "ID47",
		},
		{
			name:          "invalid proc-id - empty",
			msg:           []byte(""),
			expectedProc:  "",
			expectedError: ErrInvalidProcID,
		},
		{
			name:          "invalid proc-id - too long",
			msg:           []byte(strings.Repeat("a", 129) + " "),
			expectedProc:  "",
			expectedError: ErrInvalidProcID,
		},
	}

	for _, tc := range testcases {
		procID, err := parseProcID(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedProc, procID, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParseMsgID(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedMsg   string
		expectedError error
	}{
		{
			name:        "valid msg-id - nil",
			msg:         []byte("- "),
			expectedMsg: "",
		},
		{
			name:        "valid msg-id",
			msg:         []byte("ID47 "),
			expectedMsg: "ID47",
		},
		{
			name:          "invalid msg-id - empty",
			msg:           []byte(""),
			expectedMsg:   "",
			expectedError: ErrInvalidMsgID,
		},
		{
			name:          "invalid msg-id - too long",
			msg:           []byte(strings.Repeat("a", 33) + " "),
			expectedMsg:   "",
			expectedError: ErrInvalidMsgID,
		},
	}

	for _, tc := range testcases {
		msgID, err := parseMsgID(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedMsg, msgID, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParseStructuredData(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedSD    string
		expectedError error
	}{
		{
			name:       "valid structured-data - nil",
			msg:        []byte("- "),
			expectedSD: "",
		},
		{
			name:       "valid structured-data - example 1",
			msg:        []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] "),
			expectedSD: "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]",
		},
		{
			name:       "valid structured-data - example 2",
			msg:        []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] "),
			expectedSD: "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]",
		},
		{
			name:       "valid structured-data - no space",
			msg:        []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]"),
			expectedSD: "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]",
		},
		{
			name:          "invalid structured-data - empty",
			msg:           []byte(""),
			expectedSD:    "",
			expectedError: ErrInvalidStructuredData,
		},
		{
			name:          "invalid structured-data - missing closing bracket",
			msg:           []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011 "),
			expectedSD:    "",
			expectedError: ErrInvalidStructuredData,
		},
	}

	for _, tc := range testcases {
		sd, err := parseStructuredData(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedSD, sd, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParseStructuredDataElements(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedSD    *[]StructuredDataElement
		expectedError error
	}{
		{
			name:       "valid structured-data-elements - empty",
			msg:        []byte(""),
			expectedSD: nil,
		},
		{
			name: "valid structured-data-elements - example 1",
			msg:  []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] "),
			expectedSD: &[]StructuredDataElement{
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
			name: "valid structured-data-elements - example 2",
			msg:  []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] "),
			expectedSD: &[]StructuredDataElement{
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
			name:          "invalid structured-data-elements - missing ID",
			msg:           []byte("[ iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] "),
			expectedSD:    nil,
			expectedError: ErrInvalidStructuredData,
		},
		{
			name:          "invalid structured-data-elements - invalid parameter",
			msg:           []byte("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\" invalid] "),
			expectedSD:    nil,
			expectedError: ErrInvalidStructuredData,
		},
	}

	for _, tc := range testcases {
		sd, err := parseStructuredDataElements(string(tc.msg))
		assert.Equal(t, tc.expectedSD, sd, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestParseString(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		maxLength     int
		expectedStr   string
		expectedError error
	}{
		{
			name:        "valid string",
			msg:         []byte("test "),
			maxLength:   4,
			expectedStr: "test",
		},
		{
			name:        "valid string - nil",
			msg:         []byte("- "),
			maxLength:   0,
			expectedStr: "",
		},
		{
			name:          "invalid string - empty",
			msg:           []byte(""),
			maxLength:     0,
			expectedStr:   "",
			expectedError: ErrInvalidMessage,
		},
		{
			name:          "invalid string - too long",
			msg:           []byte("test "),
			maxLength:     3,
			expectedStr:   "",
			expectedError: ErrInvalidMessage,
		},
		{
			name:          "invalid string - no space",
			msg:           []byte("test"),
			maxLength:     0,
			expectedStr:   "",
			expectedError: ErrInvalidMessage,
		},
	}

	for _, tc := range testcases {
		str, err := parseString(bytes.NewReader(tc.msg), tc.maxLength, ErrInvalidMessage)
		assert.Equal(t, tc.expectedStr, str, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestCheckNilValue(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedNil   bool
		expectedError error
	}{
		{
			name:        "nil value",
			msg:         []byte("- "),
			expectedNil: true,
		},
		{
			name:          "nil value with invalid character",
			msg:           []byte("-a "),
			expectedNil:   false,
			expectedError: ErrInvalidNilValue,
		},
		{
			name:        "non-nil value",
			msg:         []byte("test "),
			expectedNil: false,
		},
		{
			name:          "empty value",
			msg:           []byte(""),
			expectedNil:   false,
			expectedError: ErrInvalidNilValue,
		},
	}

	for _, tc := range testcases {
		isNil, err := checkNilValue(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedNil, isNil, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func BenchmarkParse(b *testing.B) {
	p := NewParser()
	msg := []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] An application event log entry...")

	for i := 0; i < b.N; i++ {
		_, err := p.Parse(bytes.NewReader(msg))
		if err != nil {
			b.Fatal(err)
		}
	}
}
