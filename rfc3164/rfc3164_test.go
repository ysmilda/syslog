//nolint:lll
package rfc3164

import (
	"bytes"
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
			msg:  []byte("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"),
			expectedMessage: Message{
				PRI:       PRI{34},
				Timestamp: time.Date(0, time.October, 11, 22, 14, 15, 0, time.UTC),
				Hostname:  "mymachine",
				Tag:       "su",
				Content:   ": 'su root' failed for lonvick on /dev/pts/8",
			},
		},
		{
			name: "valid message - example 2 (after relay)",
			msg:  []byte("<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!"),
			expectedMessage: Message{
				PRI:       PRI{13},
				Timestamp: time.Date(0, time.February, 5, 17, 32, 18, 0, time.UTC),
				Hostname:  "10.0.0.99",
				Tag:       "",
				Content:   "Use the BFG!",
			},
		},
		{
			name: "valid message - example 3",
			msg:  []byte("<165>Aug 24 05:34:00 CST 1987 mymachine myproc[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%"),
			expectedMessage: Message{
				PRI:       PRI{165},
				Timestamp: time.Date(0, time.August, 24, 5, 34, 0, 0, time.UTC),
				Hostname:  "CST",
				Tag:       "1987 mymachine myproc",
				Content:   "[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%",
			},
		},
	}

	p := NewParser()

	for _, tc := range testcases {
		msg, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Nil(t, err, tc.name)
		assert.Equal(t, tc.expectedMessage, msg, tc.name)
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
			msg:           []byte("Aug  4 05:14:15"),
			expectedTime:  time.Time{},
			expectedError: ErrInvalidTimestamp,
		},
		{
			name:          "valid timestamp",
			msg:           []byte("Aug  4 05:14:15 "),
			expectedTime:  time.Date(0, time.August, 4, 5, 14, 15, 0, time.UTC),
			expectedError: nil,
		},
		{
			name:          "valid timestamp - empty",
			msg:           []byte(" "),
			expectedTime:  time.Time{},
			expectedError: nil,
		},
		{
			name:          "invalid timestamp - too short",
			msg:           []byte("Aug  4 05:14:1"),
			expectedTime:  time.Time{},
			expectedError: ErrInvalidTimestamp,
		},
		{
			name:          "invalid timestamp - invalid month",
			msg:           []byte("Aut  4 05:14:15 "),
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
			name:          "valid hostname",
			msg:           []byte("host "),
			expectedHost:  "host",
			expectedError: nil,
		},
		{
			name:          "invalid hostname - no space",
			msg:           []byte("host"),
			expectedHost:  "",
			expectedError: ErrInvalidHostname,
		},
		{
			name:          "invalid hostname - empty",
			msg:           []byte(""),
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

func TestParseMessage(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name            string
		msg             []byte
		expectedTag     string
		expectedContent string
	}{
		{
			name:            "valid message",
			msg:             []byte("tag: content"),
			expectedTag:     "tag",
			expectedContent: ": content",
		},
		{
			name:            "valid message - no tag",
			msg:             []byte("content"),
			expectedTag:     "",
			expectedContent: "content",
		},
		{
			name:            "valid message - no content",
			msg:             []byte("tag:"),
			expectedTag:     "tag",
			expectedContent: ":",
		},
		{
			name:            "valid message - empty",
			msg:             []byte(""),
			expectedTag:     "",
			expectedContent: "",
		},
		{
			name:            "valid message - process id",
			msg:             []byte("tag[id]: content"),
			expectedTag:     "tag",
			expectedContent: "[id]: content",
		},
	}

	for _, tc := range testcases {
		tag, content := parseMessage(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedTag, tag, tc.name)
		assert.Equal(t, tc.expectedContent, content, tc.name)
	}
}

func BenchmarkParse(b *testing.B) {
	p := NewParser()
	msg := []byte("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8")

	for i := 0; i < b.N; i++ {
		_, err := p.Parse(bytes.NewReader(msg))
		if err != nil {
			b.Fatal(err)
		}
	}
}
