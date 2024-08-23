//nolint:lll
package rfc3164

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterSeverity(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedError error
	}{
		{
			name: "severity 0",
			msg:  []byte("<0>Oct 11 22:14:15 host Message"),
		},
		{
			name: "severity 1",
			msg:  []byte("<1>Oct 11 22:14:15 host Message"),
		},
		{
			name:          "severity 2",
			msg:           []byte("<2>Oct 11 22:14:15 host Message"),
			expectedError: ErrMessageIgnored,
		},
	}

	p := NewParser(FilterSeverity(1))

	for _, tc := range testcases {
		_, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestFilterFacility(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedError error
	}{
		{
			name: "facility 0",
			msg:  []byte("<0>Oct 11 22:14:15 host Message"),
		},
		{
			name: "facility 1",
			msg:  []byte("<8>Oct 11 22:14:15 host Message"),
		},
		{
			name:          "facility 2",
			msg:           []byte("<16>Oct 11 22:14:15 host Message"),
			expectedError: ErrMessageIgnored,
		},
	}

	p := NewParser(FilterFacility(1))

	for _, tc := range testcases {
		_, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestFilterHostname(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedError error
	}{
		{
			name: "hostname match",
			msg:  []byte("<0>Oct 11 22:14:15 host Message"),
		},
		{
			name:          "hostname mismatch",
			msg:           []byte("<0>Oct 11 22:14:15 other Message"),
			expectedError: ErrMessageIgnored,
		},
	}

	p := NewParser(FilterHostname([]string{"host"}))

	for _, tc := range testcases {
		_, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}
