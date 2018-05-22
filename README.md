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

- U2F Introduction
  - FIDO
  - ECC Crypto / ECDSA
  - Supported Service
- A Glance of COTS U2F USB Tokens
  - Yubikey
  - Nitrokey
- U2F Key Wrapping Mechanism
  - What does Yubico say
  - What does FIDO say
  - U2Fishing: record the master secret of each U2F token during manufacturing process
  - Under potential surveillance
  - U2F Counter: anti-clone
- U2Fishing
  - Open Source Project 'U2F Zero' Overview
  - Hardware Overview
    - Secure Element: Atmel ATECC508A
  - Firmware Overview
  - How to Program / Factory Reset a U2F Zero
  - Key Wrapping Mechanism Introduced
  - How to steal Master Key out of a U2F Zero
  - Write some code to replay key wrapping
  - Simulation with v2f.py
  - Bypassing U2F counter detection: Faking a large counter number.
- Live Demo
  - demo.yubico.com
  - Gmail
  - Facebook
  - Github
  - Fastmail
- Counter Measures
  - reconfigure every new U2F token
  - Yubico doesn't support it yet.
  - You can reprogram U2F Zero totally on your own.
  - Clone detecting by the counter.
  - User: The indication of cloned U2F Key.
  - For website security team
    - Test result:
      - Google
      - Facebook
    - Github
    - Fastmail (No counter implemented, reported, confirmed by Fastmail Security Team and will be fixed)
    - trusted U2F token whitelist
  - Isolate each key pair within U2F token by disabling Key Wrapping mechanism.
  


