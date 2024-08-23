package rfc3164

// FilterSeverity filters out messages with a severity higher than the given severity.
func FilterSeverity(severity int) parseOption {
	return func(r *Parser) {
		r.severityFilter = &severity
	}
}

// FilterFacility filters out messages with a facility higher than the given facility.
func FilterFacility(facility int) parseOption {
	return func(r *Parser) {
		r.facilityFilter = &facility
	}
}

// FilterHostname filters out messages with a hostname that is not in the given list.
func FilterHostname(hostname []string) parseOption {
	return func(r *Parser) {
		r.hostnameFilter = hostname
	}
}
