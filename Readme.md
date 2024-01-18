# Readme
Encryption traffic packets classification demo.
The demo is based on this paper:

> Lotfollahi, Mohammad, et al. "Deep packet: A novel approach for encrypted traffic classification using deep learning." Soft Computing 24.3 (2020): 1999-2012.

#### Setup

This demo was tested successfully on i.MX93 11x11 evk. You can download the BSP from [NXP website](https://www.nxp.com/design/design-center/software/embedded-software/i-mx-software/embedded-linux-for-i-mx-applications-processors:IMXLINUX). Here are the configuration on the i.MX boards. The configuarion on PC is omitted.

1. Run `setup_env.sh` on the first installation to install python package and create the required folders.

 2. If you need to capture the traffic on the board, you should install tcpdump firstly. The installation is a bit cumbersome. You need to download the following sources code in order and compile it directly on board:
	- flex
	- bison
	- libpcap
	- tcpdump

3. Connect network cable between PC and `eth1` on i.MX93. Then, connect network cable between Internet and `eth0` on i.MX93. After this, your the network traffic from PC will gothrough i.MX93. By the way, if you want to make the board connect the Internet, you can execuate `route del default gw 0.0.0.0` to delete wrong gateway IP.

![imx93](./imx93.png)

4. Run `br0_config_with_veth.sh` to configure the soft switch function. The .sh file will create a bridge to forward eth0 and eth1. At the same time, it will create a virtual interface veth0 for debugging and display of results. If all goes well, your PC can now access the Internet through i.MX93.
#### Train model
If you already have the tflite model we provided, you can **skip the training step**.
The model should be trained on PC instead of  board.
You can modify `utils.py` to fit your dataset.

These commands show preprocess, training and test processes.
```bash
cd deepPacket
python preprocess.py --traff_type <your_type> --feature_dir ./feature_dir --pcap_dir /path/to/pcaps/

python main.py --traff_type <your_type> --feature_dir ./feature_dir/ --output_dir ./output_dir/ --mode train

python main.py --traff_type <your_type> --feature_dir ./feature_dir/ --output_dir ./output_dir/ --mode test
```
  
#### Inference on i.MX
In order to use i.MX93 NPU inference, you need to execute `vela <your_model_name>.tflite` to build the tflite model.
Then, a tflite file with `_vela` suffix is generated in the `output` folder.

You should modify `analysis_pkt.sh`. Change the `--model_path` option value to the tflite file with `_vela`.
Execute `./run_demo.sh`. 
It will start tcpdump and web server processes.

Now, you can access the report webpage by `http://<board_ip>:5000` in your PC browser.

**Notice:** The model has concept drift problem, so different training sets should be used to update the model for different network environments.