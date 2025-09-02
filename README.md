# browmal

`browmal` is a program that allows parsing a PE, Elf, or Office Document file using your web browser. The file and resulting data stays within your browser via a Go-based WASM application. It was inspired by the OMAT tool created by https://anticrypt.de. Yara scanning is not performed within the wasm environment.

The original version had a web server and yara scanning. Those will become a separate program and GitHub repository.

This programm is a proof-of-concept for tinkering with learning how to parse PE and ELF files with Go and I used the tutorial from https://d3ext.github.io/posts/malware-analysis-1/ to learn to create a parser with Go. I used the elf_view sample code from https://github.com/yalue/elf_reader/tree/master/elf_view for the Elf parser. Also, velocidex (https://github.com/Velocidex/oleparse) is used to help parse Office Documents to extract macros.

Another part of this program is training. Information on how to interpret the output will be updated over time. There is some information to get started, though it is not complete. There are some limitations on using a WASM application and I've been working on keeping the code as small as possible since it loads in the browser.

## Use cases:

- You want to start learning reverse engineering.
- You are a student and need to perform some basic reverse engineering.
- You work in an organization with a limited budget and you need to do some basic analysis of a suspicious file.

## Features

- Parse PE, Elf, and Office Document files.
- Display: file hashes, SSDeep fuzzy hash, file entropy, sections, symbols, strings, segments, program headers, relocations, dynamic linking table, malicious calls.
- Display office document macros
- Display objdump-like disassembly
- Display strings

## Motivation

I've always had an interest in creating a WASM application. I tend to learn best by creating something I would use and making something practical so I stumbled upon this idea after showing someone OMAT.

However, as I am thinking about improving on `browmal` I think about junior analysis and junior security engineers that may not have the financial or people resources to use commercial tools or are not allowed to send files outside the organization like VirusTotal or other online services for analysis. There are other tools available, though I hope this could be useful to someone. I'm also using it this semester in courses I'm teaching.

## Updates

### 20250902

Removed extraneous files and folders and only keep the offline wasm app. The WASM application is base64 encoded and saved inside the HTML file.

## Setup

Place the `index.html` and `wasm_exec.js` file in the same directory. Double-click the `index.html` file to open it in your browser. No server is required since the WASM application is embedded in the HTML file.
