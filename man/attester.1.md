% attester(1) CHARRA

# NAME

**attester**(1) - Perform remote attestation using CHARRA.

# SYNOPSIS

**attester** [*OPTIONS*]

# DESCRIPTION

**attester**(1) - The primary role of the attester in CHARRA is to act as the entity being attested. Upon receiving a challenge from the verifier, the attester gathers the requested measurements by performing a TPM quote operation. This quote includes the selected Platform Configuration Register (PCR) values, which reflect the current state of the system. The attester then sends this signed evidence back to the verifier for evaluation.

# OPTIONS

  * **-h**, **\--help**:

    Prints usage information.

  * **-c**, **\--config=PATH**:

    Loads attester config from a file.

  * **-v**, **\--verbose**:

    Set CHARRA and CoAP log-level to DEBUG.

  * **-l**, **\--log-level=LEVEL**:

    Set CHARRA log-level to LEVEL. Available are: TRACE, DEBUG, INFO, WARN, ERROR, FATAL. Default is INFO.

  * **\--coap-log-level=LEVEL**:

    Set CoAP log-level to LEVEL. Available are: DEBUG, INFO, NOTICE, WARNING, ERR, CRIT, ALERT, EMERG, CIPHERS. Default is INFO.

  * **-k**, **\--attestation-key=FORMAT:VALUE**:

    Specifies the path to the attestation key. Available are: context, handle.

  * **\--port=PORT**:

    Define a custom port.

  * **\--pcr-log=FORMAT:FILE**:

    Specifies the path to the PCR log file. Available formats are: ima, tcg-boot.

# DTLS-PSK Options:

* **-p**, **\--psk**:

    Enable DTLS protocol with PSK. By default the key 'Charra DTLS Key' and hint 'Charra Attester' are used.

* **\--psk-key=KEY**:

    Use KEY as pre-shared key for DTLS. Implicitly enables DTLS-PSK.

* **\--psk-hint=HINT**:

    Use HINT as hint for DTLS. Implicitly enables DTLS-PSK.

# DTLS-RPK Options:

Charra includes default 'keys' in the keys folder, but these are only intended for testing. They MUST be changed in actual production environments!

*  **-r**, **\--rpk**:

    Enable DTLS-RPK (raw public keys) protocol. The protocol is intended for scenarios in which public keys of either attester or verifier or both of them are pre-shared.

*  **\--rpk-private-key=PATH**:

    Specify the path of the private key used for RPK. Currently only supports DER (ASN.1) format.

    By default 'keys/attester.der' is used. Implicitly enables DTLS-RPK.

*  **\--rpk-public-key=PATH**:

    Specify the path of the public key used for RPK. Currently only supports DER (ASN.1) format.

    By default 'keys/attester.pub.der' is used. Implicitly enables DTLS-RPK.

*  **\--rpk-peer-public-key=PATH**:

    Specify the path of the reference public key of the peer, used for RPK. Currently only supports DER (ASN.1) format.

    By default 'keys/verifier.pub.der' is used. Implicitly enables DTLS-RPK.

*  **\--rpk-verify-peer=[0,1]**:

    Specify whether the peers public key shall be checked against the reference public key. 0 means no check, 1 means check. By default the check is performed.

    WARNING: Disabling the verification means that connections from any peer will be accepted. This is primarily intended for the verifier, which may not have
    the public keys of all attesters and does an identity check with the attestation response. Implicitly enables DTLS-RPK.

# TCTI commands

To specify TCTI commands for the TPM, set the 'CHARRA_TCTI' environment variable accordingly.

# CONFIGURATION FILES

CHARRA's attester can be configured using a YAML configuration file. By default, the attester automatically loads **/etc/charra/attester-config.yaml** if it exists. Other specified config files and command-line arguments override values from a config file unless **lock-config** is set to **true**.

## Configuration Structure

Below is a description of the configuration structure and its available fields:

### Top-Level: charra-attester

| Field              | Type              | Description                                                          |
| ------------------ | ----------------- | -------------------------------------------------------------------- |
| lock-config        | Boolean           | If true, disables overriding this config file                        |
| listen-ip          | String            | IP address the attester binds to (e.g., "0.0.0.0")                   |
| listen-port        | Integer           | Port number the attester listens on (default: 5683)                  |
| log-level          | String            | Log level for CHARRA. One of: TRACE, DEBUG, INFO, WARN, ERROR, FATAL |

### charra-attester.coap

| Field              | Type    | Description                                                        |
| ------------------ | ------- | ------------------------------------------------------------------ |
| log-level          | String  | Log level for CoAP. Values: EMERG, ALERT, CRIT, ERR, WARNING, etc. |

### charra-attester.coap.udp.dtls-psk

| Field  | Type    | Description                                          |
| ------ | ------- | ---------------------------------------------------- |
| enable | Boolean | Enables DTLS with pre-shared keys                    |
| hint   | String  | Identity hint sent to peer (used in PSK negotiation) |
| key    | String  | The pre-shared key used for DTLS-PSK                 |


### charra-attester.coap.udp.dtls-rpk

| Field                                 | Type         | Description                                                           |
| ------------------------------------- | ------------ | --------------------------------------------------------------------- |
| enable                                | Boolean      | Enables DTLS with raw public keys (RPK)                               |
| private-key-path                      | String       | Path to the attester's private key (DER format)                       |
| public-key-path                       | String       | Path to the attester's public key (DER format)                        |
| verify-peer-public-key                | Boolean      | Whether to verify the verifier's public key against a known reference |
| peer-public-key-path                  | String       | Path to the verifier’s public key (DER format)                        |


### charra-attester.attestation.key

| Field       | Type   | Description                                                              |
| ----------- | ------ | ------------------------------------------------------------------------ |
| format      | String | Type of key reference: context or handle                                 |
| path        | String | Path to the key context file or a TPM handle used for TPM attestation key (AK) |

### charra-attester.attestation.pcr-log

| Field    | Type   | Description                                                                |
| -------- | ------ | --------------------------- |
| ima      | String | Path to IMA logs            |
| tcg-boot | String | Path to TCG boot log        |
