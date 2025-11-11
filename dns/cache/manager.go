package cache

type Manager interface {
	Flush() error
}
