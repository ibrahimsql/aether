package payloads

// PayloadManager manages XSS payloads.
type PayloadManager struct {
	Payloads []string
}

func NewPayloadManager() *PayloadManager {
	return &PayloadManager{Payloads: []string{}}
}

func (pm *PayloadManager) LoadFromFile(path string) error {
	// TODO: Implement loading payloads from file
	return nil
}

func (pm *PayloadManager) Add(payload string) {
	pm.Payloads = append(pm.Payloads, payload)
}
