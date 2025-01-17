# App-network-ml
Application of ML in network. This is an encrypted traffic packets classification demo, which can tell us which service types are being carried by passing packets. Currently supported categories are file transfer, Web browsing, VoIP, Email and Microsoft Office.


## Setup

This demo was tested successfully on i.MX93 11x11 evk. You can download the BSP from [NXP website](https://www.nxp.com/design/design-center/software/embedded-software/i-mx-software/embedded-linux-for-i-mx-applications-processors:IMXLINUX). Here are the configuration on the i.MX boards. The configuarion on PC is omitted.

1. Run `setup_env.sh` on the first installation to install python package and create the required folders.

 2. If you need to capture the traffic on the board, you should install tcpdump firstly. The installation is a bit cumbersome. You need to download the following sources code in order and compile it directly on board:
	- flex
	- bison
	- libpcap
	- tcpdump

3. Connect network cable between PC and `eth1` on i.MX93. Then, connect network cable between Internet and `eth0` on i.MX93. After this, your the network traffic from PC will gothrough i.MX93. By the way, if you want to make the board connect the Internet, you can execuate `route del default gw 0.0.0.0` to delete wrong gateway IP.

<p align="center">
<img src="./imx93.png" width=300>
</p>

4. Run `br0_config_with_veth.sh` to configure the soft switch function. The .sh file will create a bridge to forward eth0 and eth1. At the same time, it will create a virtual interface veth0 for debugging and display of results. If all goes well, your PC can now access the Internet through i.MX93.

  
## Inference on i.MX

In order to use i.MX93 NPU inference, you need to execute `vela <your_model_name>.tflite` to build the tflite model.
Then, a tflite file with `_vela` suffix is generated in the `output` folder.

You should modify `analysis_pkt.sh`. Change the `--model_path` option value to the tflite file with `_vela`.
Execute `./run_demo.sh`. 
It will start tcpdump and web server processes.

Now, you can access the report webpage by `http://<board_ip>:5000` in your PC browser.

By the way, the model has concept drift problem, so different training sets should be used to update the model for different network environments.

## Notice
The demo is based on this paper:

> Lotfollahi, Mohammad, et al. "Deep packet: A novel approach for encrypted traffic classification using deep learning." Soft Computing 24.3 (2020): 1999-2012.