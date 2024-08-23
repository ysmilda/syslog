package rfc5424

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

// FilterAppName filters out messages with an appname that is not in the given list.
func FilterAppName(appName []string) parseOption {
	return func(r *Parser) {
		r.appNameFilter = appName
	}
}

// FilterProcID filters out messages with a procID that is not in the given list.
func FilterProcID(procID []string) parseOption {
	return func(r *Parser) {
		r.procIDFilter = procID
	}
}

// FilterMsgID filters out messages with a msgID that is not in the given list.
func FilterMsgID(msgID []string) parseOption {
	return func(r *Parser) {
		r.msgIDFilter = msgID
	}
}
