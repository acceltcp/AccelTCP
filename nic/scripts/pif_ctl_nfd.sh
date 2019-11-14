#!/bin/bash
# Copyright (C) 2015-2016 Netronome Systems, Inc.  All rights reserved.

# ENV VARS
#
# NUM_VFS - number of VFs to create
# BASE_MAC - base MAC address for netdevs, #VF masked into lower word
# NBI_MAC8_JSON - MAC config for NBI 0
# NBI_MAC9_JSON - MAC config for NBI 1
# NBI_DMA8_JSON - DMA config for NBI 0
# NBI_DMA9_JSON - DMA config for NBI 1
# NBI_TM_JSON - TM config for NBI 0 and 1
# NFPSHUTILS - Location of nfp-shutils
# DISABLE_NFD - Set to "yes" to disable
# DETECT_MAC - Set to "yes" to detect the NFP MAC config and set links to platform_*.json files for NBI init

# User-configurable parameters
USE_PMD=1
NUM_VFS=8
NFP_IP_ADDR=10.0.30.100

# (For USE_PMD=1) DUAL_PORT determines whether to use dual NIC ports
# When disabled, it allocates 1 VF per core
# When enabled, it allocates 2 VFs per core
#DUAL_PORT=0

#
# Variables
#

# Loaded from command line
firmwarefile=

# Loaded from enrivonment
NETRODIR=${NETRODIR:-/opt/netronome}
NFPPIFDIR=${NFPPIFDIR:-/opt/nfp_pif}
NFPSHUTILS=${NFPSHUTILS:-$NFPPIFDIR/scripts/shared/nfp-shutils}
DISABLE_NFD=${DISABLE_NFD:-no}
DETECT_MAC=${DETECT_MAC:-yes}
NFPPIFHOME=${NFPPIFHOME:-/dev/shm/.nfp_pif_tmp}


set -e

on_err () {
	echo "Error on line $1: err($2)"
	exit 1
}

trap 'on_err $LINENO $?' ERR

mkdir -p $NFPPIFHOME

#
# Functions
#

set_common_vars() {

  # Set BASE_MAC based on NFP_NUM (only applied for the 'USE_PMD == 0' case)
  BASE_MAC=${BASE_MAC:-"00:15:4d:0$NFP_NUM:00:"}

  # Get list of NFP cards in system
  PCI_NFP_IDS=`lspci -d 19ee:4000 -D | cut -d ' ' -f 1`
  PCI_NFP_IDS="${PCI_NFP_IDS} `lspci -d 19ee:6000 -D | cut -d ' ' -f 1`"

  # Here we get the PCI device for the provided NFP_NUM
  # we also build up a list of all the PCIe devices
  # which we use to figure out the multi pcie details
  PCIE_DETAILS=()
  PCI_ID=-1
  for id in $PCI_NFP_IDS; do
    _NFP_NUM=`ls /sys/bus/pci/drivers/nfp/$id/cpp/nfp-dev-cpp | cut -d'-' -f3`
    # PCI serial includes NFP serial and pci isl number
    _NFP_PCI_SERIAL=`lspci -s $id -vvv | grep Serial | sed -e 's/^.*Serial Number //'`
    _NFP_PCI_ISL=`echo $_NFP_PCI_SERIAL | sed -e 's/.*-.\(.\)-..\w*$/\1/'`
    _NFP_DEVICE_SERIAL=`echo ${_NFP_PCI_SERIAL:0:17}`
    PCIE_DETAILS+=("$id $_NFP_DEVICE_SERIAL $_NFP_PCI_ISL $_NFP_NUM")

    if [ $NFP_NUM == $_NFP_NUM ]; then
      NFP_PCI_SERIAL=$_NFP_PCI_SERIAL
      NFP_PCI_ISL=$_NFP_PCI_ISL
      NFP_DEVICE_SERIAL=$_NFP_DEVICE_SERIAL
      PCI_ID=$id
    fi
  done

  if [ $PCI_ID == -1 ]; then
    echo "No NFP card detected"
    exit 1
  fi

  PCI_IDS=()
  NFP_NUM_MASTER=-1
  for pd in "${PCIE_DETAILS[@]}"; do
    IFNUM=`echo $pd | cut -f3 -d ' '`
    SERIAL=`echo $pd | cut -f2 -d ' '`
    ID=`echo $pd | cut -f1 -d ' '`
    NFP_DEV=`echo $pd | cut -f4 -d ' '`
    if [ "$SERIAL" != "$NFP_DEVICE_SERIAL" ]; then
      continue
    fi
    if [ "$IFNUM" == 0 ]; then
      NFP_NUM_MASTER=$NFP_DEV
    fi
    PCI_IDS+=("$ID $IFNUM")
  done

  # Check for ARI support
  if [ -f $NFPPIFHOME/ari_support ]; then
    ARI=`cat $NFPPIFHOME/ari_support`
  else
    ARI_SUPPORT=$($NETRODIR/bin/nfp-support | grep ARI -m1)

    if [[ "$ARI_SUPPORT" == *"not supported"* ]]; then
      ARI=0
    else
      ARI=1
    fi

    echo $ARI > $NFPPIFHOME/ari_support
  fi

  if [[ "$ARI" -eq 1 ]]; then
    echo "ARI Support detected"
  else
    echo "No ARI Support found. VFs not supported."
  fi

  NBI0_PORT_MASK=0
  NBI1_PORT_MASK=0


  NFP_PHYMOD_OUT=`$NETRODIR/bin/nfp-phymod -n $NFP_NUM -E`
  for PORTSPEC in `echo "$NFP_PHYMOD_OUT" |grep "^eth" | sed -e 's/.*NBI//g' -e 's/(.*//'`; do
      PORT=`echo $PORTSPEC | sed -e 's/^.*\.//'`
      NBI=`echo $PORTSPEC | sed -e 's/\..*//'`
      if [ "$NBI" = "0" ]; then
          NBI0_PORT_MASK=$[NBI0_PORT_MASK | (1 << PORT)]
      else
          NBI1_PORT_MASK=$[NBI1_PORT_MASK | (1 << PORT)]
      fi
  done

  PLATFORM=`$NETRODIR/bin/nfp-hwinfo -n $NFP_NUM | grep assembly.model | sed 's/.*=//g'`
  VARIANT=`echo "$NFP_PHYMOD_OUT" | grep -m1 "^eth" | sed -e 's/^.* \([^ ]*\)G .*/\1GE/'`
}

set_platform_vars() {
  PHY0_CACHE_FILE=$NFPPIFHOME/phy0_mod_out_$NFP_NUM
  PHY1_CACHE_FILE=$NFPPIFHOME/phy1_mod_out_$NFP_NUM
  if [ -f $PHY0_CACHE_FILE ]; then
    PHY0_MOD_OUT=`cat $PHY0_CACHE_FILE`
  else
    PHY0_MOD_OUT=`$NETRODIR/bin/nfp-phymod -n $NFP_NUM -i 0 2>&1 | sed -n '/eth/p'`
    echo "$PHY0_MOD_OUT" > $PHY0_CACHE_FILE
  fi
  if [ -f $PHY1_CACHE_FILE ]; then
    PHY1_MOD_OUT=`cat $PHY1_CACHE_FILE`
  else
    PHY1_MOD_OUT=`$NETRODIR/bin/nfp-phymod -n $NFP_NUM -i 1 2>&1 | sed -n '/eth/p'`
    echo "$PHY1_MOD_OUT" > $PHY1_CACHE_FILE
  fi

  PHY0_ETH_COUNT=`echo "$PHY0_MOD_OUT" | grep eth | wc -l`
  PHY1_ETH_COUNT=`echo "$PHY1_MOD_OUT" | grep eth | wc -l`

  PHY0_ETH_10G=`echo "$PHY0_MOD_OUT" | grep 10G | wc -l`
  PHY1_ETH_10G=`echo "$PHY1_MOD_OUT" | grep 10G | wc -l`

  NBI0_PORT_MASK=0
  NBI1_PORT_MASK=0

  for PORTSPEC in `echo "$NFP_PHYMOD_OUT" | grep "^eth" | sed -e 's/.*NBI//g' -e 's/(.*//'`; do
      PORT=`echo $PORTSPEC | sed -e 's/^.*\.//'`
      NBI=`echo $PORTSPEC | sed -e 's/\..*//'`
      if [ "$NBI" = "0" ]; then
          NBI0_PORT_MASK=$[NBI0_PORT_MASK | (1 << PORT)]
      else
          NBI1_PORT_MASK=$[NBI1_PORT_MASK | (1 << PORT)]
      fi
  done

  NBI_TM_JSON=${NBI_TM_JSON:-nfp_nbi_tm_12x10GE.json}

  # default configs
  MAC8_CFG=hy-1x40GE-prepend.json
  DMA8_CFG=nfp_nbi8_dma_hy.json

  if [[ "$PLATFORM" == *"starfighter1"* ]] ; then
    DMA8_CFG=nfp_nbi8_dma_sf.json
    if [ "$PHY0_ETH_COUNT" -eq "1" -a "$PHY1_ETH_COUNT" -eq "0" ]; then
        MAC8_CFG=sf1-1x100GE-prepend.json
    elif [ "$PHY0_ETH_COUNT" -eq "10" -a "$PHY1_ETH_COUNT" -eq "0" ]; then
        MAC8_CFG=sf1-10x10GE-prepend.json
    elif [ "$PHY0_ETH_COUNT" -eq "2" -a "$PHY1_ETH_COUNT" -eq "0" ]; then
        MAC8_CFG=sf1-2x40GE-prepend.json
    elif [ "$PHY0_ETH_COUNT" -eq "1" -a "$PHY1_ETH_COUNT" -eq "1" ]; then
        MAC8_CFG=sf1-2x40GE-prepend.json
    elif [ "$PHY0_ETH_COUNT" -eq "4" -a "$PHY1_ETH_COUNT" -eq "4" ]; then
        MAC8_CFG=sf1-8x10GE-prepend.json
    elif [ "$PHY0_ETH_COUNT" -eq "4" -a "$PHY1_ETH_COUNT" -eq "1" ]; then
        MAC8_CFG=sf1-4x10GE-1x40GE-prepend.json
    else
        echo "Unrecognised starfighter variant $VARIANT"
        exit 1
    fi
  elif [ "$PLATFORM" = "hydrogen" ] ; then
    DMA8_CFG=nfp_nbi8_dma_hy.json
    if [ "$PHY0_ETH_COUNT" -eq "1" -a "$PHY1_ETH_COUNT" -eq "0" ]; then
        MAC8_CFG=hy-1x40GE-prepend.json
    elif [ "$PHY0_ETH_COUNT" -eq "4" -a "$PHY1_ETH_COUNT" -eq "0" ]; then
        MAC8_CFG=hy-4x10GE-prepend.json
    else
        echo "Unrecognised hydrogen variant $VARIANT"
        exit 1
    fi
  elif [ "$PLATFORM" = "lithium" ] ; then
    #DMA8_CFG=nfp_nbi8_dma_li.json
    NBI_TM_JSON="$NFPPIFDIR/etc/configs/nfp_nbi_tm_2x10GE.json"
    if [ "$PHY0_ETH_10G" -eq "1" -a "$PHY1_ETH_10G" -eq "1" ]; then
        MAC8_CFG=li-2x10GE-prepend.json
    elif [ "$PHY0_ETH_10G" -eq "0" -a "$PHY1_ETH_10G" -eq "0" ]; then
        MAC8_CFG=li-2x1GE-prepend.json
    else
        echo "Unrecognised lithium variant $VARIANT"
        exit 1
    fi
  elif [ "$PLATFORM" = "beryllium" ] ; then
    #DMA8_CFG=nfp_nbi8_dma_be.json
    if [ "$PHY0_ETH_COUNT" -eq "1" -a "$PHY1_ETH_COUNT" -eq "0" ]; then
        MAC8_CFG=be-1x40GE-prepend.json
    elif [ "$PHY0_ETH_COUNT" -eq "4" -a "$PHY1_ETH_COUNT" -eq "0" ]; then
        MAC8_CFG=be-4x10GE-prepend.json
        NBI_TM_JSON="$NFPPIFDIR/etc/configs/nbi_tm_4x10GE.json"
    elif [ "$PHY0_ETH_COUNT" -eq "1" -a "$PHY1_ETH_COUNT" -eq "1" ]; then
        MAC8_CFG=be-2x40GE-prepend.json
    elif [ "$PHY0_ETH_COUNT" -eq "4" -a "$PHY1_ETH_COUNT" -eq "1" ]; then
        MAC8_CFG=be-4x10GE-1x40GE-prepend.json
        NBI_TM_JSON="$NFPPIFDIR/etc/configs/nbi_tm_4x10GE-1x40GE.json"
    elif [ "$PHY0_ETH_COUNT" -eq "4" -a "$PHY1_ETH_COUNT" -eq "4" ]; then
        MAC8_CFG=be-8x10GE-prepend.json
        NBI_TM_JSON="$NFPPIFDIR/etc/configs/nbi_tm_8x10GE.json"
    else
        echo "Unrecognised beryllium variant $VARIANT"
        exit 1
    fi
  elif [ "$PLATFORM" = "bataan" ] ; then
    DMA8_CFG=nfp_nbi8_dma_cdp.json
    MAC8_CFG=cdp-1x100GE-2x10GE-3x40GE-prepend.json
  elif [ "$PLATFORM" = "carbon" ] ; then
    if [ "$PHY0_ETH_10G" -eq "1" -a "$PHY1_ETH_10G" -eq "1" ]; then
        MAC8_CFG=c-2x10GE-prepend.json
        NBI_TM_JSON="$NFPPIFDIR/etc/configs/nfp_nbi_tm_c_2x10GE.json"
    elif [ "$PHY0_ETH_10G" -eq "0" -a "$PHY1_ETH_10G" -eq "0" ]; then
        MAC8_CFG=c-2x25GE-prepend.json
        NBI_TM_JSON="$NFPPIFDIR/etc/configs/nfp_nbi_tm_c_2x40GE.json"
    else
        echo "Unrecognised carbon variant $VARIANT"
        exit 1
    fi
  else
    echo "Unrecognised platform $PLATFORM"
    exit 1
  fi

  # Setup links
  ##ln -sf "$NFPPIFDIR/etc/configs/$MAC8_CFG" "$NFPPIFDIR/etc/configs/platform_mac8_config.json"
  ##ln -sf "$NFPPIFDIR/etc/configs/$DMA8_CFG" "$NFPPIFDIR/etc/configs/platform_dma8_config.json"
  NBI_MAC8_JSON="$NFPPIFDIR/etc/configs/$MAC8_CFG"

  if [ $DEBUG_MODE -eq 1 ] ; then
    NBI_DMA8_JSON="$NFPPIFDIR/etc/configs/nfp_nbi8_dma_debug.json"
  else
    NBI_DMA8_JSON="$NFPPIFDIR/etc/configs/$DMA8_CFG"
  fi

  echo "Detected $PLATFORM platform, using $MAC8_CFG for MAC init"
  echo " and $DMA8_CFG for DMA init (when not in debug mode)"
}

nfd_post_load() {
  echo "Performing NFD post load operations:"
  DRIVER="nfp"
  UNUSED_DRIVER="igb_uio"
    
  # Load firmware
  
  echo -n " - Create hugeTLB FS if needed..."
  if [ `cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages` -eq 0 ];
  then
      echo 0 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
      (umount /mnt/hugetlbfs || true) 2>/dev/null
      mkdir -p /mnt/hugetlbfs
      mount -t hugetlbfs none /mnt/hugetlbfs
      echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
  fi
  echo "done"
  

  for pd in "${PCI_IDS[@]}"; do
      pci_dev=`echo $pd | cut -f1 -d ' '`
      pci_iface=`echo $pd | cut -f2 -d ' '`
      echo "NFD setup for pcie device $pci_dev (isl $pci_iface)"

      PF_SYS="/sys/bus/pci/devices/${pci_dev}"

      # Load firmware
      echo -n " - Loading UIO and ${DRIVER} modules..."
      modprobe uio
      modprobe ${DRIVER}
      echo "done"

	  #if [ "$USE_PMD" == "1" ] && [ "$DUAL_PORT" == "1" ];then
	  #	  NUM_VFS=$[NUM_VFS * 2]
	  #fi
	  
      echo -n " - Enumerating $NUM_VFS VFs..."
      echo $NUM_VFS > ${PF_SYS}/sriov_numvfs
      sleep 0.5
      echo "done"

      # Get PCI domain.bus
      PCI_DB=`cut -d: -f1,2 <<< ${pci_dev}`

      # Get list of VFs
      NFP_VF_IDS=`lspci -d 19ee:6003 -D | grep ${PCI_DB} | cut -d ' ' -f 1`

      echo -n " - Make sure VFs bound to ${DRIVER}..."
      for i in ${NFP_VF_IDS}
      do
          (echo -n "${i}" > \
              /sys/bus/pci/drivers/${UNUSED_DRIVER}/unbind || true) 2>/dev/null
          (echo -n "${i}" > \
              /sys/bus/pci/drivers/${DRIVER}/bind || true) 2>/dev/null
      done
      sleep 0.5

      # Set MAC and netdev name
      echo -n " - Configure MAC addr and name..."
      sleep 1

	  if [ "$USE_PMD" == "0" ];then
		  # (1) kernel driver module (nfp-netvf)
		  VF=0
		  eths=`find /sys/bus/pci/devices/${PCI_DB}*/net -maxdepth 1 -mindepth 1 | sed -e 's#.*/##'`
		  for eth in $eths; do
			  MAC=`printf "%s%02x" $BASE_MAC $VF`
			  ip l s dev $eth down
			  ip l s dev $eth address $MAC
			  
			  if [ "$pci_iface" == 0 ]; then
				  vf_if="vf${NFP_NUM_MASTER}_${VF}"
			  else
				  vf_if="vf${NFP_NUM_MASTER}_${pci_iface}_${VF}"
			  fi
			  ip l s dev $eth name $vf_if
			  ip l s dev $vf_if up
			  sysctl -w net.ipv6.conf.$vf_if.disable_ipv6=1
			  VF=$[VF + 1]
		  done
	  else
		  # (2) DPDK PMD driver module (vfio-pci)
		  modprobe vfio-pci
		  PCI_PREFIX=`echo $PCI_ID | cut -d':' -f2`
		  for i in $(seq 0 $[NUM_VFS - 1])
		  do
			  #			  /opt/nfp_pif/scripts/dpdk-devbind.py -b vfio-pci ${PCI_PREFIX}:0$[8+i/8].$[i%8]
			  PCI_HEX=`printf "%02x" $[8+i/8]`
			  /opt/nfp_pif/scripts/dpdk-devbind.py -b vfio-pci ${PCI_PREFIX}:${PCI_HEX}.$[i%8]
		  done

		  DEV_CNT=`ip link show | grep dpdk0 | wc -l`
		  if [ $DEV_CNT == 0 ]; then
			  ip l a dev dpdk0 type dummy
			  MAC=`$NETRODIR/bin/nfp-hwinfo -n $NFP_NUM | grep eth0.mac | sed 's/.*=//g'`
			  ip l s dev dpdk0 address $MAC
		  fi
		  ip l s dev dpdk0 up
		  ifconfig dpdk0 ${NFP_IP_ADDR}/24

		  #if [ "$USE_PMD" == "1" ] && [ "$DUAL_PORT" == "1" ];then			  
		  #	  DEV_CNT=`ip link show | grep dpdk2 | wc -l`
		  #	  if [ $DEV_CNT == 0 ]; then
		  #		  ip l a dev dpdk2 type dummy
		  #		  MAC=`$NETRODIR/bin/nfp-hwinfo -n $NFP_NUM | grep eth1.mac | sed 's/.*=//g'`
		  #		  ip l s dev dpdk2 address $MAC		  			  
		  #	  fi
		  #	  ip l s dev dpdk2 up
		  #	  ifconfig dpdk2 10.0.32.100/24
		  #fi
	  fi  
  done
  echo "done"

  echo ""
}

nfd_pre_unload() {

  if [ "$USE_PMD" == "1" ];then
	PCI_PREFIX=`echo $PCI_ID | cut -d':' -f2`
	for i in $(seq 0 $[NUM_VFS - 1])
	do
		echo "Find any VF devices to unbind from vfio-pci .. "
		if [ -d " - 0000:${PCI_PREFIX}:0$[8+i/8].$[i%8]" ]; then
		   echo "/sys/bus/pci/drivers/vfio-pci/0000:${PCI_PREFIX}:0$[8+i/8].$[i%8]"
		   /opt/nfp_pif/scripts/dpdk-devbind.py -u ${PCI_PREFIX}:0$[8+i/8].$[i%8]
		fi
	done
  fi

  for pd in "${PCI_IDS[@]}"; do
    pci_dev=`echo $pd | cut -f1 -d ' '`
    pci_iface=`echo $pd | cut -f2 -d ' '`

    PF_SYS="/sys/bus/pci/devices/${pci_dev}"

    echo "Preparing for NFD unload:"

    echo -n " - Removing VFs..."
    echo 0 > ${PF_SYS}/sriov_numvfs
    sleep 0.5
  done
  echo "done"
}

#
# Interface functions
#

load() {
    if [ "$DETECT_MAC" = "yes" ]; then
        set_platform_vars
    fi

    (. $NFPSHUTILS; appctl -n $NFP_NUM start $firmwarefile  )

    if [ "$DISABLE_NFD" = "no" ] && [ $ARI -eq 1 ]; then
        nfd_post_load
    fi

    # enable mac interfaces
    if [ -n "$NBI_MAC8_JSON" ]; then
        $NETRODIR/bin/nfp-mactool -n $NFP_NUM -m0 -u -p $NBI0_PORT_MASK
        # enable mac poll/flush
        if $NETRODIR/bin/nfp-rtsym -n $NFP_NUM -L | grep -q 'mac_cfg_active_ports_nbi0'; then
            NBIO_ACTV_CFG=`$NETRODIR/bin/nfp-rtsym -n $NFP_NUM -L | grep -E 'mac_cfg_active_ports_nbi0' | sed -e 's/\s\+.\+//'`
            $NETRODIR/bin/nfp-rtsym -n $NFP_NUM $NBIO_ACTV_CFG $NBI0_PORT_MASK
        fi
    fi
    if [ -n "$NBI_MAC9_JSON" ]; then
        $NETRODIR/bin/nfp-mactool -n $NFP_NUM -m1 -u -p $NBI1_PORT_MASK
        # enable mac poll/flush
        if $NETRODIR/bin/nfp-rtsym -n $NFP_NUM -L | grep -q 'mac_cfg_active_ports_nbi1'; then
            NBI1_ACTV_CFG=`$NETRODIR/bin/nfp-rtsym -n $NFP_NUM -L | grep -E 'mac_cfg_active_ports_nbi1' | sed -e 's/\s\+.\+//'`
            $NETRODIR/bin/nfp-rtsym -n $NFP_NUM $NBI1_ACTV_CFG $NBI1_PORT_MASK
        fi
    fi
}

unload() {
    if [ "$DETECT_MAC" = "yes" ]; then
        set_platform_vars
    fi

    # Bring down mac interfaces
    if [ -n "$NBI_MAC8_JSON" ]; then
        # disable mac poll/flush
        if $NETRODIR/bin/nfp-rtsym -n $NFP_NUM -L 2>/dev/null | grep -q 'mac_cfg_active_ports_nbi0' ; then
            NBI0_ACTV_CFG=`$NETRODIR/bin/nfp-rtsym -n $NFP_NUM -L | grep -E 'mac_cfg_active_ports_nbi0' | sed -e 's/\s\+.\+//'`
            $NETRODIR/bin/nfp-rtsym -n $NFP_NUM $NBI0_ACTV_CFG 0x0
        fi
        # disable ports
        $NETRODIR/bin/nfp-mactool -n $NFP_NUM -m0 -d -p $NBI0_PORT_MASK || true
    fi
    if [ -n "$NBI_MAC9_JSON" ]; then
        # disable mac poll/flush
        if $NETRODIR/bin/nfp-rtsym -n $NFP_NUM -L | grep -q 'mac_cfg_active_ports_nbi0' 2> /dev/null ; then
            NBI1_ACTV_CFG=`$NETRODIR/bin/nfp-rtsym -n $NFP_NUM -L | grep -E 'mac_cfg_active_ports_nbi1' | sed -e 's/\s\+.\+//'`
            $NETRODIR/bin/nfp-rtsym -n $NFP_NUM $NBI1_ACTV_CFG 0x0
        fi
        # disable ports
        $NETRODIR/bin/nfp-mactool -n $NFP_NUM -m1 -d -p $NBI1_PORT_MASK || true
    fi

    if [ "$DISABLE_NFD" = "no" ] && [ $ARI -eq 1 ]; then
        nfd_pre_unload
    fi

    echo -n "Firmware unload, NFP Reset..."
    RET=0
    if ! (bash -c ". $NFPSHUTILS; appctl -n $NFP_NUM stop") ; then
        >&2 echo "Failed to unload NFP"
        RET=1
    fi
    exit $RET
}

usage() {
    echo $"Usage:"
    echo -e "\t $0 {load|unload} <OPERATION ARGUMENTS> "
    echo -e "\t OPERATION ARGUMENTS:"
    echo -e "\t \t load [-f|--firmwarefile <fwfile>]"
    echo -e "\t \t unload"
    echo $"When envoking load option a firmwarefile file needs to be specified"
}

while [ -n "$1" ]; do
    key="$1"

    case $key in
        load)
        OPERATION="load"
        ;;
        unload)
        OPERATION="unload"
        ;;
        -f|--firmwarefile)
        firmwarefile="$2"
        shift # past argument
        ;;
        -n|--nfp)
        NFP_NUM=$2
        shift # past argument
        ;;
        -d|--debug)
        DEBUG_MODE=1
        ;;
        *)
        # unknown option
        ;;
    esac
    shift # past argument or value
done

NFP_NUM=${NFP_NUM:=0}
DEBUG_MODE=${DEBUG_MODE:=0}

set_common_vars

case $OPERATION in
  load)
      if !( [ -f "$firmwarefile" ] ); then
          echo "Firmware file not specified"
          usage
          exit 2
      fi
      load
      ;;
  unload)
      unload
      ;;
   *)
      usage
      exit 2
esac


