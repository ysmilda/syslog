//nolint:lll
package rfc5424

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithParseStructuredDataElements(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name                           string
		msg                            []byte
		expectedStructuredDataElements *[]StructuredDataElement
		expectedError                  error
	}{
		{
			name: "valid structured data elements",
			msg:  []byte("<0>1 2012-01-01T01:01:01.000000+00:00 host app - - [id1 key1=\"value1\" key2=\"value2\"][id2 key2=\"value2\"] Message"),
			expectedStructuredDataElements: &[]StructuredDataElement{
				{
					ID: "id1",
					Parameters: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
				},
				{
					ID: "id2",
					Parameters: map[string]string{
						"key2": "value2",
					},
				},
			},
		},
	}

	p := NewParser(WithParseStructuredDataElements())

	for _, tc := range testcases {
		msg, err := p.Parse(bytes.NewReader(tc.msg))
		assert.Equal(t, tc.expectedStructuredDataElements, msg.StructuredDataElements, tc.name)
		assert.Equal(t, tc.expectedError, err, tc.name)
	}
}
