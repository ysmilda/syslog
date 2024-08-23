package rfc5424

// WithParseStructuredDataElements enables parsing of structured data elements into its seperate parts.
func WithParseStructuredDataElements() parseOption {
	return func(r *Parser) {
		r.parseStructuredDataElements = true
	}
}
