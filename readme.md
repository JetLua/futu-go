# Futu API for Go

```go
package main

import (
	"futu"
	"futu/pb"
	"log"
	"os"

	_ "github.com/joho/godotenv/autoload"
)

func init() {
	log.SetFlags(log.Lshortfile)
}

func main() {
	f, err := futu.New(futu.Config{
		Addr: "127.1:11111",
		Pbk:  os.Getenv("PBK"),
		Prk:  os.Getenv("PRK"),
	})
	if err != nil {
		panic(err)
	}

	if r, err := f.SubAccPush([]uint64{281756479040555128}); err == nil {
		log.Printf("%v\n", r)
	} else {
		log.Println(err)
	}

	f.OnMsg(func(msg any) {
		switch v := msg.(type) {
		case *pb.NotifyOrder:
			log.Printf("%+v", v)
		}
	})

	f.OnErr(func(err error) {
		log.Println(err)
	})

	f.Wait()
}
```
