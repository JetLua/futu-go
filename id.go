package futu

var ID = struct {
	Init, Ping, SubAccPush, OrderCreate, Unlock,
	NotifyOrder, OrderFee, NotifyOrderFill uint32
}{
	Init:            1001,
	Ping:            1004,
	Unlock:          2005,
	SubAccPush:      2008,
	NotifyOrder:     2208,
	OrderFee:        2225,
	OrderCreate:     2202,
	NotifyOrderFill: 2218,
}
