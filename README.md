# Whisper

![Licence](https://img.shields.io/github/license/fuchuanpu/Whisper)
![Last](https://img.shields.io/github/last-commit/fuchuanpu/Whisper)
![Language](https://img.shields.io/github/languages/count/fuchuanpu/Whisper)
![Language](https://img.shields.io/github/directory-file-count/fuchuanpu/Whisper)
![Codesize](https://img.shields.io/github/languages/code-size/fuchuanpu/Whisper)

The prototype source code of the paper:  
___Realtime Robust Malicious Traffic Detection via Frequency Domain Analysis___  
Chuanpu Fu (Maintaniner), [Qi Li](https://sites.google.com/site/qili2012), [Meng Shen](https://cs.bit.edu.cn/szdw/jsml/js/shenmeng/index.htm), [Ke Xu](http://www.thucsnet.org/xuke.html).  
ACM Conference on Computer and Communications Security (CCS 2021)

``` bibtex

```

> __Latest Info:__ The readme is not completed yet :warning:.
---

## Background
Malicious traffic detection systems are designed to identify malicious traffic on the forwarding path. As a promising security paradigm, machine learning (ML) was leveraged for the _zero-day attack issue_. Due to the improper trade-off between feature _scale_ and _efficiency_, the existing can not realize _robust_ and _realtime_ detection. We present the frequency domain features, which reduce the scale of traditional per-packet features, avoid information loss in the flow-level features. Finally, in this repo. Finally, we present the Whisper prototype, an end-to-end detector in a 10 Gb scale network in this repo.

> For more details, plsease refer to our paper in ACM CCS 2021.

---
## Install

> Feel free to contact me, when something went wrong. 


### Hardware preparation  

Before software installation please check your hardware platform according to the testbed setup in the paper. Here I list some recommendations:  
- Ensure all your NICs and CPUs supports Intel DPDK, find the versions using `lspci` and `proc/cpuinfo` and check the lists in [DPDK Support](http://core.dpdk.org/supported/)
- Check the connectivity of fiber and laser modules using ICMP echo and static routing. Note that, direct connections are preferred to prevent errors.
- To adapt the packet rate of MAWI datasets, ensure the NICs support at least 10 Gbps throughput. Measuring the throughput using `iperf3` is recommended.
- At least 10 GB of memory is needed, for the DPDK huge pages. And the server for Whisper main modules needs at least 17 cores.

### Software preparation

0. __Install compile toolchain.__   
The prototype was tested in Ubuntu 18.04 and 20.04. It is compiled by `cmake` + `ninja` + `gcc`, please find the correct versions and install the tool chain using `apt-get`. 

1. __Install DPDK.__  
Whisper used DPDK for highspeed packet parsering. Therefore, please refer to the [__DPDK Offical Guide__](http://doc.dpdk.org/guides/linux_gsg/) and install the libraries. It is worth noting that, the compatibility of DPDK 21 is unknown and the version listed in the paper is preferred.

2. __Install LibPcap++.__  
Whisper used LibPcap++ encapsulated DPDK to reduce the size of the source code. Make sure the libpcap++ version is compatible with the DPDK version. Note that, the Libpcap++ with DPDK support can only be obtained via source code compiling. Here is the official the guide for [Libpcap++ Installation](https://pcapplusplus.github.io/docs/install/build-source/linux).

3. __Install PyTorch C++__  
Whisper used Pytorch C++ to implement matrix and sequence transformations. Download the Offical released form [Pytorch Release](https://pytorch.org/get-started/locally/). The ABI for CPU only is enough and make sure you selected cxx11 supported version.

4. __Install mlpcak__
Whisper used mlpack for unsupervised learning. Please used the correct commands for C++ stable version in [mlpack Installation](https://www.mlpack.org/getstarted.html).

> I will commit a script for software installation starting from a clean Ubuntu.

> The docker image for Whisper is under testing and will be public soon.

---
## Usage

Firstly, check the path of downloaded PyTorch C++ is configured in CMakeLists.txt correctly. Then compile the prototype source code.
```shell
mkdir build && cd $_
cmake -G Ninja ..
ninja
```
---
## FAQ
0. __Strange link stage warnings.__ After the compiling, we got the warnings from `ld` below, but `ninja` generated binary successfully. What is the impact of the abnormity? 
```
/usr/bin/ld: /home/libtorch/lib/libtorch_cpu.so: .dynsym local symbol at index 149 (>= sh_info of 2)
```
__Answer:__ The link stage warning is generated because of the mismatch of the compiler version for PyTorch and Whisper. You can find a closer version, but it has no side-effect from my experience.

1. __On the feasibility of deploying Whisper in cloud.__

__Answer:__ I have tried to deploy it on AWS EC2 and other commercial clouds. Finally, I succeeded with huge efforts but still cannot realize the throughput measured on the physical testbed due to the performance limitations of virtual network interfaces. Therefore, I do not recommend the deployment in a multi-tenant network because the . _If you have some advice, please contact us._

---
## Contact Me
[Chuanpu Fu](fcp20@tsinghua.edu.cn)

---
## 
