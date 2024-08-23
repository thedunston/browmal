# browmal

`browmal` is a program that allows parsing a PE file using your web browser. The file and resulting data stays within your browser. It was inspired by the OMAT tool created by https://anticrypt.de.

It is a proof-of-concept for tinkering with learning how to parse PE files with Go and used the tutorial from https://d3ext.github.io/posts/malware-analysis-1/ to learn to create a parser with Go.

However, I've always had an interest in creating a WASM application. I tend to learn best by creating something I would use and making something practical so I stumbled upon this idea after showing someone OMAT recently.

The `malicious_calls.json` file contains known function calls used by malware. The format is:

```
"functionCall":"Details about the function."
```
If the function call is found, it will be highlighted and you can click on it and get the `Details about the function`.

Initial json from: https://gist.github.com/404NetworkError/a81591849f5b6b5fe09f517efc189c1d and https://sensei-infosec.netlify.app/forensics/windows/api-calls/2020/04/29/win-api-calls-1.html.

Lots more work to do such as prettier formatting. I'm not good at that so I used ChatGPT to create that Javascript and HTML/CSS front end functionality.  I don't do a lot of front-end work.

## Setup

Place the `index.html`, `main.wasm`, `malicious_calls.json`, and `wasm_exec.js` file in the same directory on a web server. NOTE: `wasm_exec.js` comes from the standard Go download.

If you don't have a web server, you can use Python (`python3 -m http.server  8111`) or PHP (`php -S localhost:8111`) or whatever. There is also a basic web server in this repo you can use.

For the Go webserver in this repo, create a directory named `static` in the same folder as the web server binary and place the files `index.html`, `main.wasm`, `malicious_calls.json`, and `wasm_exec.js` there.

You can run the binary as is and it will listen on `http://127.0.0.1:8111` by default or specify flags:

`./websrv -ip 192.168.44.22 -port 20000`

NOTE: The provided web server doesn't use SSL.

## Compile from source
To compile the `main.go` file from source run (`-s -w` removes symbols and debug and makes the binary smaller):

```
OOS=js GOARCH=wasm go build -ldflags "-s -w"  -o main.wasm 
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

## Scanned with SemGrep - https://semgrep.dev

The findings were expected because of how MD5 and SHA1 is used to parse the headers.
```
main.go
    ❯❱ go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5
          Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is
          therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.               
          Details: https://sg.run/2xB5                                                                   
                                                                                                         
           52┆ md5_h := md5.Sum(fileBytes)
   
    ❯❱ go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
          Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is
          therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.                 
          Details: https://sg.run/XBYA                                                                     
                                                                                                           
           53┆ sha1_h := sha1.Sum(fileBytes)
                                   
    websrv/websrv.go
    ❯❱ go.lang.security.audit.net.use-tls.use-tls
          Found an HTTP server without TLS. Use 'http.ListenAndServeTLS' instead. See
          https://golang.org/pkg/net/http/#ListenAndServeTLS for more information.   
          Details: https://sg.run/dKbY                                               
                                                                                     
           ▶▶┆ Autofix ▶ http.ListenAndServeTLS(addr, certFile, keyFile, nil)
           56┆ log.Fatal(http.ListenAndServe(addr, nil))

```
