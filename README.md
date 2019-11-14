# AccelTCP

AccelTCP is a user-level TCP stack that harnesses programmable network interface cards (or NICs) as a TCP protocol accelerator. AccelTCP can offload stateful TCP operations such as connection setup and teardown as well as connection splicing that relays packets between two connections entirely on NIC. AccelTCP aims to extend the benefit of traditional NIC offloads such as TSO or LRO to short-lived connections and application-level proxying.


## System Requirements

### Hardware requirements

AccelTCP uses Netronome Agilio NICs as a smart NIC platform to offload stateful TCP operations. To enable NIC offload, you will need a machine equipped with any of the following NICs:

* [Netronome Agilio LX](https://www.netronome.com/products/agilio-lx/)
* [Netronome Agilio CX](https://www.netronome.com/products/agilio-cx/)

### Software requirements

Our current AccelTCP implementation requires the following libraries:

* libnuma
* libpthread
* librt
* libgmp
* Linux kernel headers (For Debian/Ubuntu, try `apt-get install linux-headers-$(uname -r)`)

The default I/O module for using AccelTCP is [Data Plane Development Kit (DPDK)](https://www.dpdk.org/). Please refer to [this link](https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html) to figure out the requirements for compiling AccelTCP with DPDK.

To run Netronome Agilio NICs, you need to install NFP-4xxx/NFP-6xxx SDK available at [Netronome Support Site](https://support.netronome.com/index.php). NFP SDK library requires the following dependencies:

* libftdi1
* libjansson4
* build-essential
* realpath

For more details, please refer to the following documents to figure out the requirements for running NFP SDK:
* Chapter 2 of NFP-4xxx/NFP-6xxx SDK Release Notes
* README of NFP-4xxx/NFP-6xxx SDK Run Time Environment (RTE)

### Tested Environment

AccelTCP applications have been tested on the following systems:

* Intel Xeon Gold 6142 (16-cores @ 2.6 GHz) CPU, 128GB of DDR4 DRAM, Netronome Agilio LX 2x 40GbE NIC, Ubuntu 16.0.4 LTS (Linux 4.11.0), DPDK 17.08, NFP SDK 6.0.4
* Intel Xeon E5-2650 v2 (8-cores @ 2.6 GHz) CPU, 64GB of DDR3 DRAM, Netronome Agilio LX 2x 40GbE NIC, Ubuntu 16.0.6 LTS (Linux 4.11.0), DPDK 17.08, NFP SDK 6.0.4
* Intel Xeon E5-2640 v3 (8-cores @ 2.6 GHz) CPU, 64GB of DDR3 DRAM, Netronome Agilio CX 2x 40GbE NIC, Ubuntu 16.0.4 LTS (Linux 4.10.0)

### AccelTCP with Commodity NICs (without NIC offload)

You can also run AccelTCP applications without NIC offload. This is useful to configure client applications to generate workloads with [commodity NICs that supports DPDK](http://core.dpdk.org/supported/).
AccelTCP applications have been tested on the following systems *with commodity NICs (without NIC offload)*:

* Intel Xeon E5-2640 v3 (8-cores @ 2.6 GHz) CPU, 64GB of DDR3 DRAM, Intel XL710-QDA2 2x 40GbE NIC, Ubuntu 14.04.3 LTS (Linux 3.19.0), DPDK 17.08
* Intel Xeon E5-1220 v3 (4-cores @ 3.1 GHz) CPU, 16GB of DDR3 DRAM, Intel X520-DA2 2x 10GbE NIC, Ubuntu 14.04.6 LTS (Linux 3.13.0), DPDK 17.08


## Installation

1. To use Netronome Agilio NICs, You need to first setup the following Agilio NIC softwares available at [Netronome Support Site](https://support.netronome.com/index.php). Please refer to the installation guides provided by Netronome.
* NFP-4xxx/NFP-6xxx SDK Run Time Environment (RTE)
* NFP BSP (Board Support Package)
* NFP-4xxx/NFP-6xxx SDK Ubuntu Hosted Toolchain for use with BSP on hardware

2. Enable the SR-IOV functionality and Virtualization Technologies (e.g., Intel VT-d) in the BIOS option. In addition, OS virtualization needs to be enabled in the kernel startup settings. In Ubuntu, you can add `iommu=pt intel_iommu=on` in the `GRUB_CMDLINE_LINUX` option at `/etc/default/grub`, and execute `update-grub`.

3. Update NFP SDK RTE scripts and compile NIC dataplane with NFP SDK:
```bash
cd <path_to_acceltcp>
sudo ./init_nic.sh
```

4. Run NFP SDK RTE server required to load NIC dataplane:
```bash
sudo systemctl start nfp-sdk6-rte
sudo systemctl status nfp-sdk6-rte
● nfp-sdk6-rte.service - Netronome SDK6 Run Time Environment NORMAL MODE
   Loaded: loaded (/lib/systemd/system/nfp-sdk6-rte.service; enabled; vendor preset: enabled)
      Active: active (running) since Wed 2019-11-13 22:56:23 KST; 2min 44s ago
	  ```

You can run `sudo systemctl enable nfp-sdk6-rte` to start NFP SDK RTE server automatically on reboot.

__Note:__ You can skip those installation steps (1 - 4) when you run AccelTCP on a system with commodity NICs.

## Running Applications

#### 1. Build mTCP library and applications

```bash
cd <path_to_acceltcp>
./bootstrap.sh
./configure --with-dpdk-lib=<path_to_dpdk_build> --enable-nfp
```
__Note:__ You should omit `--enable-nfp` when you run AccelTCP on a system with commodity NICs without NIC offload.

#### 2-1. Run a TCP echo server with setup and teardown offload

```bash
./load_nic.sh --server
cd apps/examples/
sudo ./msg_server -c <num_cores> --nic-offload
```

#### 2-2. Run a Layer-7 load balancer with splicing offload

```bash
./load_nic.sh --proxy
cd apps/epproxy
./lib/install_yaml.sh
make
sudo ./epproxy -s
```

#### 2-2. Run a TCP test client without NIC offload

```bash
cd apps/examples/
sudo ./msg_test <server_ip> -c <num_cores> -s <message_size> -n 1 -p <num_concurrent_conns>
```

## License
AccelTCP source code is distributed under the Modified BSD License. For more detail, please refer to the LICENSE.