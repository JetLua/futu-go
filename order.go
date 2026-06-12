package futu

import (
	"futu/pb"

	"google.golang.org/protobuf/proto"
)

type Order struct {
	futu *Futu
}

/*
查询订单费用
*/
func (o *Order) Fee(h *pb.TrdHeader, orders []string) (*pb.FeeRes, error) {
	r1, err := proto.Marshal(&pb.FeeReq{
		C2S: &pb.FeeReq_C2S{
			Header:        h,
			OrderIdExList: orders,
		},
	})
	if err != nil {
		return nil, err
	}

	r2, err := o.futu.pack(ID.OrderFee, r1)
	if err != nil {
		return nil, err
	}

	r3 := &pb.FeeRes{}
	err = proto.Unmarshal(r2, r3)
	if err != nil {
		return nil, err
	}
	return r3, nil
}

func (o *Order) Create(raw *pb.CreateOrderReq) (*pb.CreateOrderRes, error) {
	r1, err := proto.Marshal(raw)
	if err != nil {
		return nil, err
	}
	r2, err := o.futu.pack(ID.OrderCreate, r1)
	if err != nil {
		return nil, err
	}
	r3 := &pb.CreateOrderRes{}
	err = proto.Unmarshal(r2, r3)
	if err != nil {
		return nil, err
	}
	return r3, nil
}
