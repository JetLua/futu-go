package futu

var ID = struct {
	Init, Ping, SubAccPush,
	NotifyOrder, OrderFee uint32
}{
	Init:        1001,
	Ping:        1004,
	SubAccPush:  2008,
	NotifyOrder: 2208,
	OrderFee:    2225,
}
