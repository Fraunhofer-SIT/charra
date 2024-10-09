cd ~/charra/
make clean
make -j
./generate-ak.sh
(bin/attester --attestation-key context:tpm_keys/rsa_ak.ctx --pcr-log tcg-boot:logs/tcg-boot/binary_bios_measurements --pcr-log ima:logs/ima/binary_runtime_measurements &); sleep .2 ; bin/verifier -f yaml:reference-pcrs.yml --attestation-public-key tpm_keys/rsa_ak.pub --pcr-log tcg-boot:1,0 --pcr-log ima:1,0; sleep 1 ; pkill -SIGINT attester
