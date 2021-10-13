
This tool analyzes first stage of TCP handshake (SYN) and recognize operating system of client

## Build
To build sp0ky, you need to [install Rust](https://www.rust-lang.org/tools/install)

```shell
git clone https://github.com/MOL0ToK/sp0ky.git
cd sp0ky
cargo build --release

./target/release/sp0ky
```

## Run
```shell
sudo sp0ky -i <interface>
```

## Run in docker
To access host network interfaces, you should run docker container in `host` network mode
```shell
docker run --net=host -e SP0KY_INTERFACE=<interface> mol0tok/sp0ky:latest
```

## API usage

To get connection information, you can use the API on port 7564. 

Request:
```shell
curl http://localhost:7564/111.111.111.111:53155
```

Response with result:
```json
{"os":"Windows","signature":"4:116+12:0:1360:64240:8:mss,nop,ws,nop,nop,sok:10:000000010"}
```

Or without:
```json
{}
```

## Fingerprint (signature)
In addition to operating system information, this tool generates a fingerprint that you can use for additional processing.

Fingerprint format: `IP_VERSION:TTL+HOPS:IP_OPTIONS_LENGTH:MSS:TCP_WINDOW_SIZE:TCP_WINDOW_SCALE:TCP_OPTIONS:IP_FLAGS:TCP_FLAGS`

Example: `4:116+12:0:1360:64240:8:mss,nop,ws,nop,nop,sok:10:000000010`

## Similar tools
* [p0f](https://github.com/p0f/p0f)
* [satori](https://github.com/xnih/satori)
* [zardaxt](https://github.com/NikolaiT/zardaxt)

## TODO
- [x] Operating system recognition
- [ ] Network adapter recognition by MTU