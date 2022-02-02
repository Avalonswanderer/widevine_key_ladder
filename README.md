# Widevine Key Ladder Script

Dependencies:
- `Python3`
- `python3-pycryptodome`

Python script mimicking the Widevine key ladder starting from the Device Key up to Content keys. This script can either start from the Device Key or the Device RSA Key.

```
usage: widevine_key_ladder.py [-h] [--device_key DEVICE_KEY] [--encryption_context ENCRYPTION_CONTEXT]
                              [--mac_context MAC_CONTEXT] [--enc_device_rsa_key ENC_DEVICE_RSA_KEY]
                              [--device_rsa_key_iv DEVICE_RSA_KEY_IV] [--cert CERT]
                              [--enc_session_key ENC_SESSION_KEY]
                              [--encryption_context_session ENCRYPTION_CONTEXT_SESSION]
                              [--mac_context_session MAC_CONTEXT_SESSION]
                              [--loadkeys_buffer LOADKEYS_BUFFER] [-n NUM_CONTENT_KEYS] [--server_key]

optional arguments:
  -h, --help            show this help message and exit
  --device_key DEVICE_KEY
                        clear device key in hex from the Keybox.
  --encryption_context ENCRYPTION_CONTEXT
                        file with the encryption context from GenerateDerivedKeys.
  --mac_context MAC_CONTEXT
                        file with the mac context from GenerateDerivedKeys.
  --enc_device_rsa_key ENC_DEVICE_RSA_KEY
                        file with the encrypted Device RSA Key from RewrapDeviceRSAKey.
  --device_rsa_key_iv DEVICE_RSA_KEY_IV
                        IV in hex for the encrypted Device RSA Key from RewrapDeviceRSAKey.
  --cert CERT           file with the clear certificate.
  --enc_session_key ENC_SESSION_KEY
                        file with the encrypted session key.
  --encryption_context_session ENCRYPTION_CONTEXT_SESSION
                        file with the encryption context from DeriveKeysFromSessionKey.
  --mac_context_session MAC_CONTEXT_SESSION
                        file with the mac context from DeriveKeysFromSessionKey
  --loadkeys_buffer LOADKEYS_BUFFER
                        file with the Loadkeys buffer containing the encrypted content keys.
  -n NUM_CONTENT_KEYS, --num_content_keys NUM_CONTENT_KEYS
                        number of content key in LoadKeys.
  --server_key          set if there is a server key in LoadKeys.
```