//nolint:lll
package rfc5424

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
			msg:  []byte("<0>1 2012-01-01T01:01:01.000000+00:00 host app - - - Message"),
		},
		{
			name: "severity 1",
			msg:  []byte("<1>1 2012-01-01T01:01:01.000000+00:00 host app - - - Message"),
		},
		{
			name:          "severity 2",
			msg:           []byte("<2>1 2012-01-01T01:01:01.000000+00:00 host app - - - Message"),
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
			msg:  []byte("<0>1 2012-01-01T01:01:01.000000+00:00 host app - - - Message"),
		},
		{
			name: "facility 1",
			msg:  []byte("<8>1 2012-01-01T01:01:01.000000+00:00 host app - - - Message"),
		},
		{
			name:          "facility 2",
			msg:           []byte("<16>1 2012-01-01T01:01:01.000000+00:00 host app - - - Message"),
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
			name: "passed",
			msg:  []byte("<0>1 2012-01-01T01:01:01.000000+00:00 host - - - - Message"),
		},
		{
			name:          "ignored",
			msg:           []byte("<0>1 2012-01-01T01:01:01.000000+00:00 other - - - - Message"),
			expectedError: ErrMessageIgnored,
		},
	}

	p := NewParser(FilterHostname([]string{"host"}))

	for _, tc := range testcases {
		_, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestFilterAppName(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedError error
	}{
		{
			name: "passed",
			msg:  []byte("<0>1 2012-01-01T01:01:01.000000+00:00 - app - - - Message"),
		},
		{
			name:          "ignored",
			msg:           []byte("<0>1 2012-01-01T01:01:01.000000+00:00 - other - - - Message"),
			expectedError: ErrMessageIgnored,
		},
	}

	p := NewParser(FilterAppName([]string{"app"}))

	for _, tc := range testcases {
		_, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestFilterProcID(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedError error
	}{
		{
			name: "passed",
			msg:  []byte("<0>1 2012-01-01T01:01:01.000000+00:00 - - proc - - Message"),
		},
		{
			name:          "ignored",
			msg:           []byte("<0>1 2012-01-01T01:01:01.000000+00:00 - - other - - Message"),
			expectedError: ErrMessageIgnored,
		},
	}

	p := NewParser(FilterProcID([]string{"proc"}))

	for _, tc := range testcases {
		_, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}

func TestFilterMsgID(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name          string
		msg           []byte
		expectedError error
	}{
		{
			name: "passed",
			msg:  []byte("<0>1 2012-01-01T01:01:01.000000+00:00 - - - msg - Message"),
		},
		{
			name:          "ignored",
			msg:           []byte("<0>1 2012-01-01T01:01:01.000000+00:00 - - - other - Message"),
			expectedError: ErrMessageIgnored,
		},
	}

	p := NewParser(FilterMsgID([]string{"msg"}))

	for _, tc := range testcases {
		_, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}
