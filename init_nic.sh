#! /bin/bash

if [ -f /lib/systemd/system/nfp-sdk6-rte.service ]; then
	cp /lib/systemd/system/nfp-sdk6-rte.service /lib/systemd/system/nfp-sdk6-rte.service.backup
	cp nic/scripts/nfp-sdk6-rte.service /lib/systemd/system/nfp-sdk6-rte.service
else
	echo "Cannot find /lib/systemd/system/nfp-sdk6-rte.service.. please check if NFP SDK and BSP is installed"
	exit 1
fi

if [ -f /opt/nfp_pif/scripts/pif_ctl_nfd.sh ]; then
	cp /opt/nfp_pif/scripts/pif_ctl_nfd.sh /opt/nfp_pif/scripts/pif_ctl_nfd.sh.backup
	cp nic/scripts/pif_ctl_nfd.sh /opt/nfp_pif/scripts/pif_ctl_nfd.sh
	cp nic/scripts/dpdk-devbind.py /opt/nfp_pif/scripts/dpdk-devbind.py
else
	echo "Cannot find /opt/nfp_pif/scripts/pif_ctl_nfd.sh.. please check if NFP SDK and BSP is installed"
	exit 1
fi

cd nic/setup_teardown; ./build_p4; cd ../..
if [ ! -f nic/setup_teardown/src/build/dataplane.nffw ]; then
	echo "Failed to build NIC dataplane for connection setup and teardown offload"
	exit 1
fi

cd nic/splice; ./build_p4; cd ../..
if [ ! -f nic/splice/src/build/splice.nffw ]; then
	echo "Failed to build NIC dataplane for connection splicing offload"
	exit 1
fi

echo "---------------------------------------"
echo "Finished initializing runtime services/scripts and building NIC dataplane"
echo "---------------------------------------"
