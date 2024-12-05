# i.MX DDoS Blocker (imx-ddb)

DDoS attack blocker on i.MX9, based on ML model and DPDK fast packets forwarding.

When you reproduce this project, you may need a Linux host, so that you can train model, build sources and handle an i.MX board.
Of course, an i.MX9 board is necessary to run imx-ddb.

## Linux host setup
The imx-ddb requires specific Python and Tensorflow version. Under different version, especially different Tensorflow version, some API may be not adaptable and you should modify code based on corresponding version. Therefore, we recommend using conda to manage Python and its package versions.

Miniconda is used for creating isolated Python env to train and convert model.
This documentation can guide you to install miniconda on your Linux server: https://docs.conda.io/en/latest/miniconda.html#.

Once you have completed the installation, you can create a new env and install required Python packages by running:
```
conda create -n imx-ddb python=3.9
conda activate imx-ddb

pip3 install -r sources/model/requirements.txt
```


## Model training
[lucid-ddos](https://github.com/doriguzzi/lucid-ddos/) is chosen as DDoS attack detection model in this project.
And we used public DDoS attacker dataset to train ML model. By default, it was [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html) and we also pushed it in sample-dataset folder.


```
cd sources/model
# preprocess dataset
python3 lucid_dataset_parser_dpkt.py -d ../../sample-dataset
# load dataset to train model
python3 lucid_cnn.py -t ../../sample-dataset -e 200
```

## Convert TF model to TFlite
Execute the following command to quantize the model, which can let it run in the TFlite on the board.
```
python3 lucid_convert.py ../../output/LUCID-ddos-CIC2019.h5 ../../output/LUCID-ddos-CIC2019-quant-int8.tflite ../../sample-dataset/dataset_train.hdf5
```

## Make l2capfwd
To make l2capfwd from source, you need to install toolchain and DPDK SDK on your Linux server.
This [README](https://github.com/NXP/dpdk/blob/22.11-qoriq/nxp/README) may guide you to complete these work.

After that, the PKG_CONFIG_PATH and toolchain path in `sources/env_setup_imx95`(for i.MX95) or `sources/env_setup`(for i.MX93) should be modified based on your environment.

Now, let environment variables effective:
```
# for imx93
source env_setup
# or, for imx95
source env_setup_imx95
```

Make it:
```
cd sources
make
```

If the path is correct and DPDK and toolchain are installed properly, you will get `l2capfwd` and `test` ELF file for aarch64 under `build` folder.


## Deploy to board
Before you continue, please make sure that model has been trained and converted properly and l2fwd is ready.

### Board environment setup

Enter u-boot to configure DPDK for i.MX95:
```
u-boot> edit mmcargs
edit: setenv bootargs ${cpuidle} ${jh_clk} ${mcore_args} console=${console} root=${mmcroot} default-hugepagesz=2m hugepagesz=2m hugepages=448 iommu.passthrough=1 mem=4096M

u-boot> saveenv
u-boot> boot
```

When first running it on default Linux BSP, you should install Flask, a lightweight WSGI web application framework for Python, to support for WebUI.
```bash
pip install Flask==3.1.0
```

### Start up imx-ddb
Then, start up the demo on i.MX boards:
```bash
python3 run_demo.py
```

It will create a VF and bind it with DPDK.
Then, start three processes: l2capfwd, AI inference and WebUI.

Users can access WebUI via `http://<board_ip>:5000`.
