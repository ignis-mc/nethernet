# Interop harness

`run.sh` builds the Go command in `go/` and the Mojo echo examples, then runs
every listener/dialer combination on loopback. See
[docs/interop.md](../docs/interop.md) for what the cases cover.

```sh
pixi run -e interop interop
```

The Go side by hand:

```sh
cd interop/go && go build -o bin/interop .
bin/interop listen -bind 127.0.0.1:7551            # echo listener, LAN discovery
bin/interop dial -target 127.0.0.1:7551 -identity  # dialer that checks echoes
bin/interop http-listen -bind 127.0.0.1:19132      # echo listener, HTTP signaling
bin/interop http-dial -url http://127.0.0.1:19132 -identity
```
