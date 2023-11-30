cd ~/charra/
make clean
make -j
(bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT attester
