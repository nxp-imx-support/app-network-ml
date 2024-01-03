Add `lucid_convert.py` and `tfl_lucid_predict.py` for model converting and inference on i.MX boards.

### Quick Guide
#### Setup
Configure the environment according to `README.md`

#### Model Training
You should train the model firstly. The existing model under the `output` folder may be outdated, so it cannot be directly used for inference.

`python lucid_cnn.py --train sample-dataset -e <epocs>`

#### Convert
Check `keras_model`, `out_tflite` and `dataset_folder` in `lucid_convert.py`

Run:
`python lucid_convert.py`

#### Inference

`python tfl_lucid_predict.py -p ./sample-dataset/ -m ./output/10t-10n-DOS2019-LUCID-quant-uint8.tflite`

*P.S. Inference on live traffic is currently not supported.*