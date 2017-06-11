# U2Fishing: Potential Security Threat Introduced by U2F Key Wrapping Mechanism

A possible real world clone attack demo regarding U2F key.


[![](https://img.youtube.com/vi/axKrtrOTfcY/0.jpg)](https://www.youtube.com/watch?v=axKrtrOTfcY)


Universal 2nd Factor (U2F) is an open authentication standard that strengthens and simplifies two-factor authentication and has been used by Facebook, Google, Github etc.

The keys stored in U2F tokens with secure element chips are considered impossible to be extracted. However, the capability of key pairs storage is limited by secure element chips, FIDO U2F standard allows a key wrapping mechanism which enables unlimited key pairs with limited storage. It's considered safe, but not with an evil manufacturer.

In this talk, we will give a real-world example of U2F phishing attack by retrieving the master secret from an open source U2F token during the manufacturing process and then give that U2F token to a victim user. Then we can clone that U2F token by implementing the same key wrapping mechanism with the master secret recorded. We will give a demo that Github, Gmail, Facebook can be affected using this kind of U2Fishing method.

Some countermeasures will be discussed. Investigating some websites that provide U2F as a two-factor authentication method, we found out that some of them haven't implemented cloning detection function which is recommended by FIDO Alliance so that U2Fishing victims will not be aware of when the attack is started.

This attack will still work even if cryptography secure element chip such as Atmel ATECC508A is used by U2F token with key wrapping mechanism.

It's recommended that end users should at least do a master secret regeneration process when given a new U2F token with key wrapping mechanism. It's currently unavailable for Yubikey.

## Outline

1. U2F Introduction
  1. FIDO
  2. ECC Crypto / ECDSA
  3. Supported Service
2. A Glance of COTS U2F USB Tokens
  1. Yubikey
  2. Nitrokey
3. U2F Key Wrapping Mechanism
  1. What does Yubico say
  2. What does FIDO say
  3. U2Fishing: record the master secret of each U2F token during manufacturing process
  4. Under potential surveillance
  5. U2F Counter: anti-clone
4. U2Fishing
  1. Open Source Project 'U2F Zero' Overview
  2. Hardware Overview
  - Secure Element: Atmel ATECC508A
  3. Firmware Overview
  4. How to Program / Factory Reset a U2F Zero
  5. Key Wrapping Mechanism Introduced
  6. How to steal Master Key out of a U2F Zero
  7. Write some code to replay key wrapping
  8. Simulation with v2f.py
  9. Bypassing U2F counter detection: Faking a large counter number.
5. Live Demo
  1. demo.yubico.com
  2. Gmail
  3. Facebook
  4. Github
  5. Fastmail
6. Counter Measures
  1. reconfigure every new U2F token
  2. Yubico doesn't support it yet.
  3. You can reprogram U2F Zero totally on your own.
  4. Clone detecting by the counter.
  5. User: The indication of cloned U2F Key.
  6. For website security team
    - Test result:
    1. Google
    2. Facebook
    3. Github
    4. Fastmail (No counter implemented, reported, confirmed by Fastmail Security Team and will be fixed)
    - trusted U2F token whitelist
  7. Isolate each key pair within U2F token by disabling Key Wrapping mechanism.
  
