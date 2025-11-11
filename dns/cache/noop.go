package cache

type noopManager struct{}

func newNoopManager() *noopManager {
	return &noopManager{}
}

func (n *noopManager) Flush() error {
	return nil
}
