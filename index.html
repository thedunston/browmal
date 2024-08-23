# malwasm

`malwasm` is a program that allows parsing a PE file using your web browser. The file and resulting data stays within your browser. It was inspired by the OMAT tool created by https://anticrypt.de.

It is a proof-of-concept for tinkering with learning how to parse PE files with Go and used the tutorial from https://d3ext.github.io/posts/malware-analysis-1/ to learn to create a parser with Go.

However, I've always had an interest in creating a WASM application. I tend to learn best by creating something I would use and making something practical so I stumbled upon this idea after showing someone OMAT recently.

The `malicious_calls.json` file contains known function calls used by malware. The format is:

```
"functionCall":"Details about the function."
```
If the function call is found, it will be highlighted and you can click on it and get the `Details about the function`.

Lots more work to do such as prettier formatting. I'm not good at that so I used ChatGPT to create that Javascript and HTML/CSS front end functionality.  I don't do a lot of front-end work.

## Setup

Place the `index.html`, `main.wasm`, `malicious_calls.json`, and `wasm_exec.js` file in the same directory on a web server. NOTE: `wasm_exec.js` comes from the standard Go download.

If you don't have a web server, you can use Python (`python3 -m http.server  8111`) or PHP (`php -S localhost:8111`) or whatever. There is also a basic web server in this repo you can use.

For the Go webserver in this repo, create a directory named `static` in the same folder as the web server binary and place the files `index.html`, `main.wasm`, `malicious_calls.json`, and `wasm_exec.js` there.

You can run the binary as is and it will listen on `http://127.0.0.1:8111` by default or specify flags:

`./websrv -ip 192.168.44.22 -port 20000`

NOTE: The provided web server doesn't use SSL.

## Compile from source
To compile the `main.go` file from source run:

```
GOOS=js GOARCH=wasm go build -o main.wasm
```

If you change the name of `main.wasm` then update it in the `index.html` file at:

```
WebAssembly.instantiateStreaming(fetch("main.wasm"), go.importObject).then(result => {
```

### Buld the web server.
Build the web server:

```
go build websrv.go
```
If you need to compile for another architecture then use:

```
GOOS=windows go build webserver.go
```
etc.
