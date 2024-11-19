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
1. prepare rust environment
```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
2. install kernel headers
```shell
sudo apt-get install linux-headers-$(uname -r)
```
3. build module
```shell
cd module
make
```
4. install module
```shell
sudo make install
```
5. build cli
```shell
cd cli
cargo build
```
6. run cli
```shell
sudo ./target/debug/cli
```