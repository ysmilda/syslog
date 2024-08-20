package rfc5424

type parseOption func(*RFC5424)

func WithParseStructuredDataElements() parseOption {
	return func(r *RFC5424) {
		r.parseStructuredDataElements = true
	}
}
