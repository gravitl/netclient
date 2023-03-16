package networking

import "sync"

// ifaceCache - keeps the best found interfaces between peers based on public key
var ifaceCache sync.Map
