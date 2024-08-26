#!/bin/bash

# If not exists vela model, build it first.
if [ ! -e ./model/LUCID-ddos-CIC2019-quant-int8_vela.tflite ]; then
  echo "Start vela building"
  cd model
  vela ./LUCID-ddos-CIC2019-quant-int8.tflite
  mv ./output/LUCID-ddos-CIC2019-quant-int8_vela.tflite ./
  rm -r ./output
  cd -
  echo "End vela building"
fi

if [ ! -x ./l2capfwd ]; then
  chmod +x ./l2capfwd
fi

echo "Start l2capfwd process"
./l2capfwd -c 0x3 -n 2 --vdev 'net_enetqos' --vdev 'net_enetfec' -- -p 0x3 -P -T 5 --no-mac-updating > ./debug.log 2>&1 &
l2capfwd_pid=$!

cd model
echo "Start AI inference process"
python3 model_inference_main.py --model ./LUCID-ddos-CIC2019-quant-int8_vela.tflite -e /usr/lib/libethosu_delegate.so > ./debug.log 2>&1 &
infer_pid=$!
cd -

cd webui
echo "Start Web UI"
python3 web_main.py > debug.log 2>&1 &
webui_pid=$!
cd -

echo "l2capfwd_pid=$l2capfwd_pid"
echo "infer_pid=$infer_pid"
echo "webui_pid=$webui_pid"

function handle_sigint {
    echo "Handle SIGINT"
    kill -2 $l2capfwd_pid
    wait $l2capfwd_pid
    echo "l2capfwd end"

    kill -2 $infer_pid
    wait $infer_pid
    echo "infer_pid end"

    kill -2 $webui_pid
    wait $webui_pid
    echo "Web UI end"

    exit
}

trap handle_sigint SIGINT

# loop for waiting signal
while true; do 
  sleep 17
done

# wait $l2capfwd_pid
# echo "l2capfwd end"
# wait $infer_pid
# echo "infer_pid end"
# wait $webui_pid
# echo "Web UI end"
