cd ~/charra/
make clean
make -j
(bin/attester &); sleep .2 ; bin/verifier -f yaml:reference-pcrs.yml ; sleep 1 ; pkill -SIGINT attester
