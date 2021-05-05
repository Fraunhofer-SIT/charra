# Warning
The keys in this folder are only supposed to be used for testing, in actual production environments they MUST be changed!

# Generating keys:
* Generate keypair: `openssl ecparam -genkey -name prime256v1 -out <name>.der -outform DER`
* Generate public key file: `openssl ec -in <name>.der -inform DER -pubout -out <name>.pub.der -outform DER`
