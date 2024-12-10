//nolint:lll
package rfc3164

import (
	"bytes"
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
			input: []byte("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"),
			expected: &Message{
				PRI:       PRI{34},
				Timestamp: time.Date(0, time.October, 11, 22, 14, 15, 0, time.UTC),
				Hostname:  "mymachine",
				Tag:       "su",
				Content:   ": 'su root' failed for lonvick on /dev/pts/8",
			},
		},
		{
			name:  "valid message - example 2 (after relay)",
			input: []byte("<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!"),
			expected: &Message{
				PRI:       PRI{13},
				Timestamp: time.Date(0, time.February, 5, 17, 32, 18, 0, time.UTC),
				Hostname:  "10.0.0.99",
				Tag:       "",
				Content:   "Use the BFG!",
			},
		},
		{
			name:  "valid message - example 3",
			input: []byte("<165>Aug 24 05:34:00 CST 1987 mymachine myproc[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%"),
			expected: &Message{
				PRI:       PRI{165},
				Timestamp: time.Date(0, time.August, 24, 5, 34, 0, 0, time.UTC),
				Hostname:  "CST",
				Tag:       "1987 mymachine myproc",
				Content:   "[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%",
			},
		},
	}

	for _, tc := range testcases {
		msg, err := NewDecoder(bytes.NewReader(tc.input)).Decode()
		assert.Nil(t, err, tc.name)
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
			input:    []byte("Aug  4 05:14:15"),
			expected: time.Time{},
			err:      ErrInvalidTimestamp,
		},
		{
			name:     "valid timestamp",
			input:    []byte("Aug  4 05:14:15 "),
			expected: time.Date(0, time.August, 4, 5, 14, 15, 0, time.UTC),
			err:      nil,
		},
		{
			name:     "valid timestamp - empty",
			input:    []byte(" "),
			expected: time.Time{},
			err:      nil,
		},
		{
			name:     "invalid timestamp - too short",
			input:    []byte("Aug  4 05:14:1"),
			expected: time.Time{},
			err:      ErrInvalidTimestamp,
		},
		{
			name:     "invalid timestamp - invalid month",
			input:    []byte("Aut  4 05:14:15 "),
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
			name:     "valid hostname",
			input:    []byte("host "),
			expected: "host",
			err:      nil,
		},
		{
			name:     "invalid hostname - no space",
			input:    []byte("host"),
			expected: "",
			err:      ErrInvalidHostname,
		},
		{
			name:     "invalid hostname - empty",
			input:    []byte(""),
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

func TestParseMessage(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name    string
		input   []byte
		tag     string
		content string
	}{
		{
			name:    "valid message",
			input:   []byte("tag: content"),
			tag:     "tag",
			content: ": content",
		},
		{
			name:    "valid message - no tag",
			input:   []byte("content"),
			tag:     "",
			content: "content",
		},
		{
			name:    "valid message - no content",
			input:   []byte("tag:"),
			tag:     "tag",
			content: ":",
		},
		{
			name:    "valid message - empty",
			input:   []byte(""),
			tag:     "",
			content: "",
		},
		{
			name:    "valid message - process id",
			input:   []byte("tag[id]: content"),
			tag:     "tag",
			content: "[id]: content",
		},
	}

	for _, tc := range testcases {
		tag, content := decodeMessage(bytes.NewReader(tc.input))
		assert.Equal(t, tc.tag, tag, tc.name)
		assert.Equal(t, tc.content, content, tc.name)
	}
}

func BenchmarkParse(b *testing.B) {
	msg := []byte("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8")
	for i := 0; i < b.N; i++ {
		_, err := NewDecoder(bytes.NewReader(msg)).Decode()
		if err != nil {
			b.Fatal(err)
		}
	}
}
