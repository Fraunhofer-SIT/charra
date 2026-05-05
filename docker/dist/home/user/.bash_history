cd ~/charra/
make clean
make -j
./generate-ak.sh
(bin/attester --config charra-attester-config.yml &); sleep .2 ; bin/verifier --config charra-verifier-config.yml ; sleep 1 ; pkill -SIGINT attester
