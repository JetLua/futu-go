package futu

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"futu/pb"
	"io"
	"log"
	"net"
	"time"

	"google.golang.org/protobuf/proto"
)

type Config struct {
	Addr, Pbk, Prk string
}

type Futu struct {
	uid    uint64
	c      net.Conn
	end    chan struct{}
	n      uint32
	rsa    *RSA
	aes    *AES
	pool   bytes.Buffer
	tasks  map[uint32]chan []byte
	err    chan error
	msgFns []func(any)
	errFns []func(error)
}

func New(cfg Config) (*Futu, error) {
	rsa, err := NewRSA(cfg.Pbk, cfg.Prk)
	if err != nil {
		return nil, err
	}

	c, err := net.Dial("tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}

	f := &Futu{
		c:      c,
		n:      1,
		rsa:    rsa,
		end:    make(chan struct{}),
		err:    make(chan error),
		tasks:  make(map[uint32]chan []byte, 10),
		msgFns: make([]func(any), 0),
		errFns: make([]func(error), 0),
	}

	go f.loop()

	err = f.init()

	if err != nil {
		return nil, err
	}

	return f, nil
}

func (f *Futu) init() error {
	r1, err := proto.Marshal(&pb.InitReq{
		C2S: &pb.InitReq_C2S{
			ClientID:      "1",
			ClientVer:     1,
			RecvNotify:    new(true),
			PacketEncAlgo: proto.Int32(2),
		},
	})

	if err != nil {
		return err
	}

	r2, err := f.pack(ID.Init, r1)
	if err != nil {
		return err
	}

	r3 := &pb.InitRes{}
	err = proto.Unmarshal(r2, r3)
	if err != nil {
		return err
	}

	f.uid = r3.S2C.LoginUserID
	f.aes = NewAES(r3.S2C.ConnAESKey, *r3.S2C.AesCBCiv)

	go f.ping(time.Duration(r3.S2C.KeepAliveInterval))

	return nil
}

func (f *Futu) ping(t time.Duration) {
	ticker := time.NewTicker(time.Second * t)
	defer ticker.Stop()

	for range ticker.C {
		r1, err := proto.Marshal(&pb.Ping{
			C2S: &pb.Ping_C2S{
				Time: time.Now().Unix(),
			},
		})
		if err != nil {
			f.emit(err)
			continue
		}
		r2, err := f.pack(ID.Ping, r1)
		if err != nil {
			f.emit(err)
			continue
		}
		r3 := &pb.Pong{}
		err = proto.Unmarshal(r2, r3)
		if err != nil {
			f.emit(err)
			continue
		}
	}
}

/*
封包协议
*/
func (f *Futu) pack(id uint32, raw []byte) ([]byte, error) {
	n := f.n
	f.n += 1
	hash := sha1.Sum(raw)
	if id == ID.Init {
		raw = f.rsa.Encrypt(raw)
	} else {
		raw = f.aes.Encrypt(raw)
	}
	l := len(raw)
	p := headerPool.Get().(*[]byte)
	defer headerPool.Put(p)

	header := *p
	clear(header)

	copy(header[0:], "FT")
	binary.LittleEndian.PutUint32(header[2:], id)
	binary.LittleEndian.PutUint32(header[8:], n)
	binary.LittleEndian.PutUint32(header[12:], uint32(l))
	copy(header[16:], hash[:])

	c := chanPool.Get().(chan []byte)
	defer chanPool.Put(c)
	f.tasks[n] = c
	defer delete(f.tasks, n)

	_, err := f.c.Write(header)
	if err != nil {
		return nil, err
	}

	_, err = f.c.Write(raw)
	if err != nil {
		return nil, err
	}

	return <-c, nil
}

func (f *Futu) loop() {
	data := make([]byte, 2048)

	for {
		n, err := f.c.Read(data)
		if err != nil {
			log.Println(err)
			f.end <- struct{}{}
			break
		}
		f.pool.Write(data[:n])
		f.handle()
	}
}

func (f *Futu) SubAccPush(ids []uint64) (*pb.SubAccPushRes, error) {
	r1, err := proto.Marshal(&pb.SubAccPushReq{
		C2S: &pb.SubAccPushReq_C2S{
			AccIDList: ids,
		},
	})
	if err != nil {
		return nil, err
	}

	r2, err := f.pack(ID.SubAccPush, r1)
	if err != nil {
		return nil, err
	}

	r3 := &pb.SubAccPushRes{}
	err = proto.Unmarshal(r2, r3)
	if err != nil {
		return nil, err
	}

	return r3, nil
}

func (f *Futu) OnMsg(fn func(msg any)) {
	f.msgFns = append(f.msgFns, fn)
}

func (f *Futu) OnErr(fn func(err error)) {
	f.errFns = append(f.errFns, fn)
}

func (f *Futu) emit(raw any) {
	switch v := raw.(type) {
	case error:
		for _, fn := range f.errFns {
			fn(v)
		}
	default:
		for _, fn := range f.msgFns {
			fn(v)
		}
	}
}

func (f *Futu) handle() {
	data, err := io.ReadAll(&f.pool)
	if err != nil {
		f.emit(err)
		return
	}

	for {
		size := len(data)
		// 数据长度小于协议头
		if size < 44 {
			f.pool.Write(data)
			return
		}

		if string(data[:2]) != "FT" {
			log.Println("协议解析失败")
			return
		}

		l := int(binary.LittleEndian.Uint32(data[12:16]))
		total := 44 + l

		// 数据不够放弃解析
		if size < total {
			f.pool.Write(data)
			return
		}

		id := binary.LittleEndian.Uint32(data[2:6])
		n := binary.LittleEndian.Uint32(data[8:12])

		var body []byte
		body = data[44:total]
		if id == ID.Init {
			body = f.rsa.Decrypt(body)
		} else {
			body = f.aes.Decrypt(body)
		}
		// 关联任务
		task := f.tasks[n]

		if task != nil {
			task <- body
		}

		switch id {
		case ID.NotifyOrder:
			r1 := &pb.NotifyOrder{}
			err := proto.Unmarshal(body, r1)
			if err != nil {
				f.emit(err)
			} else {
				log.Println(id)
				f.emit(r1)
			}
		}

		if size > total {
			data = data[total:]
		} else {
			return
		}
	}
}

func (f *Futu) Wait() {
	<-f.end
}
