//nolint:lll
package rfc3164

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
				PRI:       PRI{34},
				Timestamp: time.Date(0, time.October, 11, 22, 14, 15, 0, time.UTC),
				Hostname:  "mymachine",
				Tag:       "su",
				Content:   ": 'su root' failed for lonvick on /dev/pts/8",
			},
			expected: "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
		},
		{
			name: "valid message - example 2 (after relay)",
			input: Message{
				PRI:       PRI{13},
				Timestamp: time.Date(0, time.February, 5, 17, 32, 18, 0, time.UTC),
				Hostname:  "10.0.0.99",
				Tag:       "",
				Content:   "Use the BFG!",
			},
			expected: "<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!",
		},
		{
			name: "valid message - example 3",
			input: Message{
				PRI:       PRI{165},
				Timestamp: time.Date(0, time.August, 24, 5, 34, 0, 0, time.UTC),
				Hostname:  "CST",
				Tag:       "1987 mymachine myproc",
				Content:   "[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%",
			},
			expected: "<165>Aug 24 05:34:00 CST 1987 mymachine myproc[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%",
		},
	}

	for _, tc := range testcases {
		var buf bytes.Buffer
		_, err := NewEncoder(&buf).Encode(tc.input)
		assert.Nil(t, err, tc.name)
		assert.Equal(t, tc.expected, buf.String(), tc.name)
	}
}
