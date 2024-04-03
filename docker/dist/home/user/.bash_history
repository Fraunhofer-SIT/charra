cd ~/charra/
make clean
make -j
./generate-ak.sh
(bin/attester --attestation-key tpm_keys/rsa_ak.ctx &); sleep .2 ; bin/verifier -f yaml:reference-pcrs.yml --attestation-public-key tpm_keys/rsa_ak.pub ; sleep 1 ; pkill -SIGINT attester
