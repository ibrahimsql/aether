package report

// Reporter handles output and reporting.
type Reporter struct{}

func NewReporter() *Reporter {
	return &Reporter{}
}

func (r *Reporter) WritePlain(result string) error {
	// TODO: Implement plain text reporting
	return nil
}

func (r *Reporter) WriteJSON(result interface{}) error {
	// TODO: Implement JSON reporting
	return nil
}

func (r *Reporter) WriteHAR(result interface{}) error {
	// TODO: Implement HAR reporting
	return nil
}
