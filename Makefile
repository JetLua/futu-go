run:
	protoc -I __proto__ --go_out=./pb --go_opt=paths=source_relative __proto__/*.proto
