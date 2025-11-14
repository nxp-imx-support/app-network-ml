#!/bin/bash
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

# TODO : Add pip dependency checking: Flask, posix_ipc

export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH

PLAT_IMX93EVK="imx93evk"
PLAT_IMX95EVK="imx95evk"
PLAT_IMX943OB="imx943-orangebox"
SUPPORT_PLATFORMS=("${PLAT_IMX95EVK}" "${PLAT_IMX93EVK}" "${PLAT_IMX943OB}")
USE_NPU=false
L2CAPFWD_APP="./l2capfwd"
MODEL_APP_DIR="./model"
MODEL_APP="model_inference_main.py"
MODEL_NAME="LUCID-ddos-CIC2019-quant-int8.tflite"
WEBUI_APP_DIR="./webui"
WEBUI_APP="web_main.py"
QUIT_FLAG=0
declare -A PIDS

get_host_ip() {
    ip -o addr show | awk '/inet /{print $4}' | cut -d'/' -f1 | grep -v '^127\.' | grep -v '^169\.' | head -1
}

handle_signal() {
    echo "Recv quit signal, exit..."
    QUIT_FLAG=1
}

detect_running_platform() {
    hostname | tr -d '\n'
}

config_imx95_dpdk() {
    # Check kpage_ncache module
    if ! lsmod | grep -q kpage_ncache; then
        echo "Loading kpage_ncache.ko."
        modprobe kpage_ncache || return 1
    fi

    # Get PF PCI addresses
    pf_pci_addrs=()
    while read -r line; do
        if [[ $line == *"drv=fsl_enetc4"* ]]; then
            pf_pci_addrs+=(${line%% *})
        fi
    done < <(dpdk-devbind.py -s)
    echo "PF PCI addresses are: ${pf_pci_addrs[@]}"

    # Create VF for each PF
    for pf_addr in "${pf_pci_addrs[@]}"; do
        echo 1 > "/sys/bus/pci/devices/$pf_addr/sriov_numvfs"
    done

    # Get VF information
    vf_pci_addrs=()
    vf_dev_name=()
    dpdk_configure_flag=0
    while read -r line; do
        if [[ $line == *"drv=fsl_enetc_vf"* ]]; then
            parts=($line)
            vf_pci_addrs+=(${parts[0]})
            vf_dev_name+=(${parts[3]#*:})
        fi
        [[ $line == *"drv=uio_pci_generic"* ]] && dpdk_configure_flag=1
    done < <(dpdk-devbind.py -s)

    if (( dpdk_configure_flag )); then
        echo "DPDK VFs have been configured. Skip."
        return 0
    fi

    echo "VF PCI addresses are: ${vf_pci_addrs[@]}"
    echo "VF devices are: ${vf_dev_name[@]}"

    # Configure DPDK devices
    for dev in "${vf_dev_name[@]}"; do
        ip link set $dev down
    done

    dpdk-devbind.py -b uio_pci_generic ${vf_pci_addrs[0]} ${vf_pci_addrs[1]}
    ip link set eth0 vf 0 trust on
    ip link set eth1 vf 0 trust on

    echo "Configure finished."
    return 0
}

config_imx93_dpdk() {
    if ! lsmod | grep -q kpage_ncache; then
        echo "Loading kpage_ncache.ko."
        # modprobe kpage_ncache || return 1
        insmod /root/kpage_ncache.ko || return 1
    fi

    mkdir -p /dev/hugepages
    mount -t hugetlbfs hugetlbfs /dev/hugepages
    echo 448 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
    return $?
}

config_imx943_dpdk() {
    if ! lsmod | grep -q kpage_ncache; then
        echo "Loading kpage_ncache.ko."
        modprobe kpage_ncache || return 1
    fi

    if [[ $(ip link show br0 2>/dev/null) != "" ]]; then
        echo "VF has already configured, skip."
        return 0
    fi

    ip link add name br0 type bridge
    ip link set dev swp0 master br0
    ip link set dev swp1 master br0
    ip link set dev br0 up
    ip link set dev swp0 up
    ip link set dev swp1 up

    echo 2 > /sys/bus/pci/devices/0000:00:00.0/sriov_numvfs

    sleep 5

    local eth3_mac=$(ip link show eth3 | grep -oE 'link/ether ([0-9a-f]{2}:){5}[0-9a-f]{2}' | awk '{print $2}')
    echo -e "\033[32mDPDK port0 MAC address: ${eth3_mac}\033[0m"
    local eth4_mac=$(ip link show eth4 | grep -oE 'link/ether ([0-9a-f]{2}:){5}[0-9a-f]{2}' | awk '{print $2}')
    echo -e "\033[32mDPDK port1 MAC address: ${eth4_mac}\033[0m"

    ip link set eth3 down
    ip link set eth4 down

    sleep 5

    dpdk-devbind.py -b uio_pci_generic 0000:00:08.0
    dpdk-devbind.py -b uio_pci_generic 0000:00:10.0

    ip link set eth0 vf 0 trust on
    ip link set eth0 vf 1 trust on
    return 0
}

build_model_imx93() {
    local original_dir=$PWD
    MODEL_NAME="LUCID-ddos-CIC2019-quant-int8_vela.tflite"
    
    if [[ ! -f "$MODEL_APP_DIR/$MODEL_NAME" ]]; then
        echo "Start vela building."
        cd "$MODEL_APP_DIR" || return 1
        vela ./LUCID-ddos-CIC2019-quant-int8.tflite
        mv ./output/"$MODEL_NAME" .
        rm -rf output
        cd "$original_dir" || return 1
        echo "End vela building."
    fi
    
    [[ -f "$MODEL_APP_DIR/$MODEL_NAME" ]] && return 0
    echo "No NPU model for i.MX93"
    return 1
}

build_model_imx95() {
    MODEL_NAME="LUCID-ddos-CIC2019-neutron-converted.tflite"
    [[ -f "$MODEL_APP_DIR/$MODEL_NAME" ]] && return 0
    echo "No NPU model for i.MX95"
    return 1
}

build_model_imx943() {
    return 1
}

execute_demo_loop() {
    local hostname=$1
    local original_dir=$PWD

    # Start l2capfwd
    [[ ! -x $L2CAPFWD_APP ]] && chmod 770 "$L2CAPFWD_APP"
    echo "Start l2capfwd process"
    
    local l2cap_args
    if [[ $hostname == "${PLAT_IMX93EVK}" ]]; then
        l2cap_args="-c 0x3 -n 2 --vdev net_enetqos --vdev net_enetfec -- -p 0x3 -P -T 5 --no-mac-updating"
    elif [[ $hostname == "${PLAT_IMX95EVK}" ]]; then
        l2cap_args="-c 0x3 -n 2 -- -p 0x3 -P -T 5 --no-mac-updating"
    elif [[ $hostname == "${PLAT_IMX943OB}" ]]; then
        l2cap_args="-c 0x3 -n 1 -- -p 0x3 -T 5 --next-hop-mac-updating"
    fi

    echo "${L2CAPFWD_APP} ${l2cap_args}"
    $L2CAPFWD_APP $l2cap_args > debug.log 2>&1 &
    PIDS["l2capfwd"]=$!
    echo "l2capfwd pid: ${PIDS[l2capfwd]}"

    # Start model inference
    cd "$MODEL_APP_DIR" || return
    echo "Start AI inference process"
    
    local infer_cmd
    if $USE_NPU; then
        case $hostname in
            "${PLAT_IMX93EVK}") 
                lib="/usr/lib/libethosu_delegate.so" 
                ;;
            "${PLAT_IMX95EVK}") 
                lib="/usr/lib/libneutron_delegate.so" 
                ;;
            "${PLAT_IMX943OB}") 
                lib="/usr/lib/libneutron_delegate.so" 
                ;;
        esac
        infer_cmd="python3 $MODEL_APP --model $MODEL_NAME -e $lib"
    else
        infer_cmd="python3 $MODEL_APP --model $MODEL_NAME"
    fi

    echo "Python cmd: ${infer_cmd}"
    eval $infer_cmd > debug.log 2>&1 &
    PIDS["inference"]=$!
    echo "inference pid: ${PIDS[inference]}"

    # Start WebUI
    cd "$original_dir/$WEBUI_APP_DIR" || return
    python3 $WEBUI_APP > debug.log 2>&1 &
    PIDS["webui"]=$!
    echo "webui pid: ${PIDS[webui]}"
    echo -e "\033[32m*****WebUI listen on $(get_host_ip):5000*****\033[0m"
    echo "Ctrl C to exit"

    cd "$original_dir" || return

    # Wait for exit
    while (( QUIT_FLAG == 0 )); do
        for proc in "${!PIDS[@]}"; do
            if ! kill -0 ${PIDS[$proc]} 2>/dev/null; then
                QUIT_FLAG=1
                break
            fi
        done
        sleep 1
    done

    # Cleanup
    for proc in "${!PIDS[@]}"; do
        kill -TERM ${PIDS[$proc]} 2>/dev/null
        wait ${PIDS[$proc]}
        echo "$proc exit."
    done

    # Check return codes
    for proc in "${!PIDS[@]}"; do
        # Return code checking would need special handling as we can't retrieve after wait
        echo "Runtime log in $proc"
    done

    echo "All exit."
}

main() {
    trap handle_signal SIGINT SIGTERM
    local host_name=$(detect_running_platform)

    if ! printf '%s\n' "${SUPPORT_PLATFORMS[@]}" | grep -qx "$host_name"; then
        echo "[INFO] The current platform is not supported. Current platform: $host_name."
        return 1
    fi

    local config_status=0
    # Have checked if the host locates at SUPPORT_PLATFORMS
    case $host_name in
        "${PLAT_IMX95EVK}")
            config_imx95_dpdk || config_status=1
            if $USE_NPU && (( config_status == 0 )); then
                build_model_imx95 || config_status=1
            fi
            ;;
        "${PLAT_IMX93EVK}")
            config_imx93_dpdk || config_status=1 
            if $USE_NPU && (( config_status == 0 )); then
                build_model_imx93 || config_status=1
            fi
            ;;
        "${PLAT_IMX943OB}")
            config_imx943_dpdk || config_status=1
            
            if $USE_NPU && (( config_status == 0)); then
                build_model_imx943 || config_status=1
            fi
            ;;
        *)
            echo "[INFO] Unsupported platform."
            return 1
    esac
    echo "config_status: $config_status"
    if (( config_status == 0 )); then
        execute_demo_loop "$host_name" 
    else
        echo "Configuration error!"
    fi
}

main "$@"
