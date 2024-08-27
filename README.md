# browmal

`browmal` is a program that allows parsing a PE or Elf file using your web browser. The file and resulting data stays within your browser via a Go-based WASM application. It was inspired by the OMAT tool created by https://anticrypt.de. Yara scanning is not performed within the wasm environment, it is performed by the builtin Go web server and rules by Yara-Forge (https://yarahq.github.io/).

It is a proof-of-concept for tinkering with learning how to parse PE and ELF files with Go and I used the tutorial from https://d3ext.github.io/posts/malware-analysis-1/ to learn to create a parser with Go. I used the elf_view sample code from https://github.com/yalue/elf_reader/tree/master/elf_view for the Elf parser.

## Scanned with SemGrep - https://semgrep.dev

## Use cases:

- You want to start learning reverse engineering.
- You are a student and need to perform some basic reverse engineering.
- You work in an organization with a limited budget and you need to do some basic analysis of a suspicious file.
- With the Yara scanning (currently Linux only), you can check to see if a program has known signatures of malicious activity.

## Motivation

I've always had an interest in creating a WASM application. I tend to learn best by creating something I would use and making something practical so I stumbled upon this idea after showing someone OMAT recently.

However, as I am thinking about improving on `browmal` I think about junior analysis and junior security engineers that may not have the financial or people resources to use commercial tools or are not allowed to send files outside the organization for analysis. There are other tools available, though I hope that could be useful to someone.

## TODO

- [X] Yara Scanning (Currently Linux only). (The server takes a few seconds to start as it compiles the rules)
- [X] Extract Macros from Office Documents - https://github.com/unixfreak0037/officeparser
- [ ] Yara Scanning - compiling rules on windows.
- [ ] Add a flag to download new Yara Forge rulesets or a button in the browser
- [ ] Page to create/edit Yara rules?
- [ ] Redesign the malicious calls popup
- [ ] Send files to IntelOwl (https://intelowlproject.github.io/) Another tool that can perform analysis of files and can keep it local
- [ ] Save file scans
- [ ] Create a program to send files to `browmal`
- [ ] Add more learning material

## Updates

### 20240827
The `no-server-required` folder contains an `index.html` file and `wasm_exec.js` file that doesn't require a web server and it doesn't have Yara scanning. The WASM application is embedded as a base64 variable. CORS blocks access to loading the local `winapi.json` and `linuxsyscalls.json` files so those are also embedded.

### 20240826
The Symbols table contains information about the various Win32 API calls and Linux syscalls and appears at the bottom of the results page. The Linux syscalls documentation comes from the https://www.man7.org/ man pages website (ongoing integration). The Windows API calls comes from the https://github.com/reverseame/winapi-categories?tab=readme-ov-file Windows API and Syscalls categories Project which contains a JSON file of the Win32 API. Those can help understand the behavior of the file.

The Yara rules are the full set from the Yara Forge site. It is the best repository of Yara rules available. You can add your own rules in the `rules` directory, as well. You can add individual files or one file with multiple rules, just be sure the file has a `.yara` or `.yar` extension.

The `malicious_calls.json` file contains known function calls used by malware. The format is:

```
"functionCall":"Details about the function."
```
If the function call is found, it will be highlighted and you can click on it and get the `Details about the function`.

Initial json from: https://gist.github.com/404NetworkError/a81591849f5b6b5fe09f517efc189c1d and https://sensei-infosec.netlify.app/forensics/windows/api-calls/2020/04/29/win-api-calls-1.html.

Lots more work to do such as prettier formatting. I'm not good at that so I used ChatGPT to create that Javascript and HTML/CSS front end functionality.  I don't do a lot of front-end work enough to learn JS in-depth.

### Elf Report
![Shows an ELF file scan report.](/assets/elf.png?raw=true "Shows an ELF file scan report.")

###  PE Report
![Shows Toggle on with symbols on the left and the description of it on the right..](/assets/symbols.png?raw=true "Shows a Toggle on with symbols on the left and the description of it on the right.")

### Macro Extracted
![Shows the macro code that was extracted.](/assets/macro.png?raw=true "Shows the macro code that was extracted.")

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

## Buld the web server.

Build the web server:

```
go build websrv.go
```
If you need to compile for another architecture then use:

```
GOOS=windows go build webserver.go
```
etc.

## Yara scanning (Linux Only)
```
cd with-yara-scan
go mod init browmal
go mod tidy
go build srv.go
