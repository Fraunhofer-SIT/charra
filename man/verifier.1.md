% verifier(1) CHARRA

# NAME

**verifier**(1) - Perform remote attestation using CHARRA.

# SYNOPSIS

**verifier** [*OPTIONS*]

# DESCRIPTION

**verifier**(1) - The verifier initiates and manages the attestation process. The verifier sends a challenge to the attester, requesting evidence in the form of a TPM quote, which contains cryptographic measurements (PCR values) of the attested system's state. The verifier then evaluates the received evidence against reference values to assess the system’s trustworthiness.

# OPTIONS

  * **-h**, **\--help**:

    Prints usage information.

  * **-c**, **\--config=PATH**:

    Loads verifier config from a file.

  * **-v**, **\--verbose**:

    Set CHARRA and CoAP log-level to DEBUG.

  * **-l**, **\--log-level=LEVEL**:

    Set CHARRA log-level to LEVEL. Available are: TRACE, DEBUG, INFO, WARN, ERROR, FATAL. Default is INFO.

  * **\--coap-log-level=LEVEL**:

    Set CoAP log-level to LEVEL. Available are: DEBUG, INFO, NOTICE, WARNING, ERR, CRIT, ALERT, EMERG, CIPHERS. Default is INFO.

  * **-i**, **\--ip=IP**:

    Connect to IP instead of doing the attestation on localhost.

  * **\--port=PORT**:

    Define a custom port.

  * **-t**, **\--timeout=SECONDS**:

    Wait up to SECONDS for the attestation answer. Default is 30 seconds.

  * **-k**, **\--attestation-public-key=PATH**:

    Specifies the path to the public portion of the attestation key.

  * **-f**, **\--pcr-file=FORMAT:PATH**:

    Read reference PCRs from PATH in a specified FORMAT. Available is: yaml.

  * **-s**, **\--pcr-selection=X1[+X2...]**:

     Specifies which PCRs to check on the attester. Each X refers to a PCR bank that begins with the algorithm, followed by a ':' and a comma-separated list of PCRs.

  * **\--pcr-log=FORMAT:START,COUNT**:

    Specifies the desired PCR log format with a starting index and the number of logs. If 'START' is 0, an empty log is requested. If 'COUNT' is 0, all logs beginning with 'START' are requested. Available formats are: ima, tcg-boot.

  * **-g**, **\--hash-algorithm=ALGORITHM**:

    The hash algorithm used to digest the tpm quote.

# DTLS-PSK Options:

* **-p**, **\--psk**:

    Enable DTLS protocol with PSK. By default the key 'Charra DTLS Key' and identity 'Charra Verifier' are used.

* **\--psk-key=KEY**:

    Use KEY as pre-shared key for DTLS. Implicitly enables DTLS-PSK.

* **\--psk-identity=IDENTITY**:

    Use IDENTITY as identity for DTLS. Implicitly enables DTLS-PSK.

# DTLS-RPK Options:

Charra includes default 'keys' in the keys folder, but these are only intended for testing. They MUST be changed in actual production environments!

*  **-r**, **\--rpk**:

    Enable DTLS-RPK (raw public keys) protocol. The protocol is intended for scenarios in which public keys of either attester or verifier or both of them are pre-shared.

*  **\--rpk-private-key=PATH**:

    Specify the path of the private key used for RPK. Currently only supports DER (ASN.1) format.

    By default 'keys/verifier.der' is used. Implicitly enables DTLS-RPK.

*  **\--rpk-public-key=PATH**:

    Specify the path of the public key used for RPK. Currently only supports DER (ASN.1) format.

    By default 'keys/verifier.pub.der' is used. Implicitly enables DTLS-RPK.

*  **\--rpk-peer-public-key=PATH**:

    Specify the path of the reference public key of the peer, used for RPK. Currently only supports DER (ASN.1) format.

    By default 'keys/attester.pub.der' is used. Implicitly enables DTLS-RPK.

*  **\--rpk-verify-peer=[0,1]**:

    Specify whether the peers public key shall be checked against the reference public key. 0 means no check, 1 means check. By default the check is performed.

    WARNING: Disabling the verification means that connections from any peer will be accepted. This is primarily intended for the verifier, which may not have
    the public keys of all attesters and does an identity check with the attestation response. Implicitly enables DTLS-RPK.

# TCTI commands

To specify TCTI commands for the TPM, set the 'CHARRA_TCTI' environment variable accordingly.

# CONFIGURATION FILES
CHARRA's verifier can be configured using a YAML configuration file. If no configuration file is explicitly provided via --config, the verifier attempts to load **/etc/charra/verifier-config.yaml**
if present. Other specified config files and command-line arguments override values from a config file unless **lock-config** is set to **true**.

Configuration Structure Overview
The root field in the YAML file must be charra-verifier. Below is a description of the key configuration fields and their purpose.

## Configuration Structure

Below is a description of the configuration structure and its available fields:

### Top-Level: charra-verifier

| Field            | Type         | Description                                                           |
| ---------------- | ------------ | --------------------------------------------------------------------- |
| lock-config      | Boolean      | If true, prevents overriding config values via CLI arguments.         |
| target-host      | String       | IP of the attester to connect.                                        |
| target-port      | Integer      | Port to connect to on the attester side (default: 5683).              |
| log-level        | String       | Log level for CHARRA. Values: TRACE, DEBUG, INFO, WARN, ERROR, FATAL. |

### charra-verifier.coap

| Field                         | Type         | Description                                                        |
| ----------------------------- | ------------ | ------------------------------------------------------------------ |
| log-level                     | String       | Log level for CoAP. Values: EMERG, ALERT, CRIT, ERR, WARNING, etc. |
| io-process-time-ms            | Integer      | Time in milliseconds to wait for CoAP I/O processing.              |

### charra-verifier.coap.udp.dtls-psk

| Field    | Type    | Description                                                       |
| -------- | ------- | ----------------------------------------------------------------- |
| enable   | Boolean | Enables DTLS with pre-shared keys.                                |
| identity | String  | Identity used in DTLS-PSK.                                        |
| key      | String  | The pre-shared key for DTLS communication.                        |

### charra-verifier.coap.udp.dtls-rpk

| Field                                 | Type         | Description                                                         |
| --------------------------------      | ------------ | ------------------------------------------------------------------- |
| enable                                | Boolean      | Enables DTLS with raw public keys (RPK).                            |
| private-key-path                      | String       | Path to the verifier's private key in DER format.                   |
| public-key-path                       | String       | Path to the verifier's public key in DER format.                    |
| verify-peer-public-key                | Boolean      | If true, the attester’s peer public key will be verified.           |
| peer-public-key-path                  | String       | Path to the known attester peer public key.                         |

### charra-verifier.attestation

| Field                                                    | Type            | Description                                                        |
| ---------------------------------------------------      | --------------- | ------------------------------------------------------------------ |
| response-timeout                                         | Integer         | Max time (in seconds) to wait for an attestation response.         |
| use-tpm-for-random-nonce-generation                      | Boolean         | Use TPM to generate nonce; otherwise use software RNG.             |
| tpm-sig-key-id                                           | String          | Identifier for the TPM signing key.                                |
| tpm-quote-signature-hash-algorithm                       | String          | Hash algorithm used for TPM quote signature (e.g., sha256).        |
| public-key-path                                          | String          | Path to the attester’s public portion of the Attestation Key (AK). |

### charra-verifier.attestation.reference-pcr-file

| Field  | Type   | Description                                                                                |
| ------ | ------ | ------------------------------------------------------------------------------------------ |
| path   | String | Path to the file containing reference PCR values.                                          |
| format | String | Format of the reference file. Supported: yaml.                                             |

### charra-verifier.attestation.tpm-pcr-selection

| Field  | Type       | Description                                                                            |
| ------ | ---------- | -------------------------------------------------------------------------------------- |
| sha1   | List\[int] | PCR indices to select from the SHA-1 bank.                                             |
| sha256 | List\[int] | PCR indices to select from the SHA-256 bank.                                           |
| sha384 | List\[int] | PCR indices to select from the SHA-384 bank.                                           |
| sha512 | List\[int] | PCR indices to select from the SHA-512 bank.                                           |

### charra-verifier.attestation.pcr-log.ima

| Field          | Type             | Description                                                                                 |
| -------------- | ---------------- | ------------------------------------------------------------------------------------------- |
| start          | Integer          | Starting index for IMA logs. 0 means empty response.                                        |
| count          | Integer          | Number of IMA log entries to request. 0 means request all entries starting from start.      |

### charra-verifier.attestation.pcr-log.tcg-boot

| Field          | Type             | Description                                                                                      |
| -------------- | ---------------- | ------------------------------------------------------------------------------------------------ |
| start          | Integer          | Starting index for TCG boot logs. 0 means empty response.                                        |
| count          | Integer          | Number of TCG boot log entries to request. 0 means request all entries starting from start.      |
