# mini-fire
Kernel-level stateful inspection firewall

## structure
- cli 
    - user interface
- module
    - kernel module


## target
- [ ]cli
- [ ]module
    - [x]hook register
    - [x]install module
    - [ ]state machine
        - [ ]TCP
        - [ ]UDP
        - [ ]ICMP
    - [x]rule filter


## How to use
1. prepare
    - linux kernel source
    - linux kernel headers
    - gcc
    - make
    - rustc
2. build