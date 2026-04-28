package config

type NoopManager struct{}

func (n *NoopManager) Configure(_ string, _ Config) error {
	return nil
}
