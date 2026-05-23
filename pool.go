package futu

import "sync"

var headerPool = sync.Pool{
	New: func() any {
		b := make([]byte, 44)
		return &b
	},
}
