package futu

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"futu/pb"
	"log"
	"net"
	"time"

	"google.golang.org/protobuf/proto"
)

type Config struct {
	Addr, Pbk, Prk string
}

type Futu struct {
	uid   uint64
	c     net.Conn
	end   chan struct{}
	n     uint32
	rsa   *RSA
	aes   *AES
	pool  bytes.Buffer
	tasks map[uint32]chan []byte
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
		c:     c,
		n:     1,
		rsa:   rsa,
		end:   make(chan struct{}),
		tasks: make(map[uint32]chan []byte, 10),
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
		log.Println("ticker")
		r1, err := proto.Marshal(&pb.Ping{
			C2S: &pb.Ping_C2S{
				Time: time.Now().Unix(),
			},
		})
		if err != nil {
			log.Println(err)
			continue
		}
		r2, err := f.pack(ID.Ping, r1)
		if err != nil {
			log.Println(err)
			continue
		}
		r3 := &pb.Pong{}
		err = proto.Unmarshal(r2, r3)
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("%v\n", r3)
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

func (f *Futu) handle() {
	data := f.pool.Bytes()
	for {
		size := len(data)
		// 数据长度小于协议头
		if size < 44 {
			f.pool.Reset()
			f.pool.Write(data)
			return
		}

		if string(data[:2]) != "FT" {
			log.Println("协议解析失败")
			return
		}

		l := int(binary.LittleEndian.Uint32(data[12:16]))
		total := 44 + l

		if size < total {
			f.pool.Reset()
			f.pool.Write(data)
			return
		}

		id := binary.LittleEndian.Uint32(data[2:6])
		n := binary.LittleEndian.Uint32(data[8:12])

		task := f.tasks[n]
		// 没有关联任务
		if task != nil {
			r := data[44:total]
			log.Printf("n: %d\nid: %d\n", n, id)
			if id == ID.Init {
				r = f.rsa.Decrypt(r)
				task <- r
			} else {
				r = f.aes.Decrypt(r)
				task <- r
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
