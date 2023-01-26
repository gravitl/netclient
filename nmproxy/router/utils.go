package router

type routerPair struct {
	ID          string
	source      string
	destination string
	masquerade  bool
}
