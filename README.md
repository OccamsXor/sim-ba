# sim-ba
(Sim)ulate (Ba)zar Loader

## Introduction
Sim-Ba is an in-memory PE Loader designed to simulate the behaviour of Bazar Loader. It downloads the payload from C2 URL and uses Process Hollowing method to inject downloaded PE into the new process created in suspended state. Process Hollowing is already a well-known, commonly used injection [technique](https://attack.mitre.org/techniques/T1055/012/). Sim-Ba is a modified version of another Process Hollowing repository: [idan1288/ProcessHollowing32-64](https://github.com/idan1288/ProcessHollowing32-64) 

## Usage
```shell
.\sim-ba.exe [Target executable] [Payload URL] 
```
