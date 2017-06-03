# -*- coding: utf8
import time, os, sys, array, binascii, signal, random, hashlib, hmac

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def sha256(msg):
    m = hashlib.new('sha256')
    m.update(msg)
    return m.digest()

def websafe_base64_decode(data):
    return data.replace("-","+").replace("_","/").decode("base64")

def get_write_mask(key):
    m = hashlib.new('sha256')
    m.update(key + '\x15\x02\x01\x00\xee\x01\x23' + ('\x00'*57))
    h1 = m.hexdigest()
    m = hashlib.new('sha256')
    m.update(binascii.unhexlify(h1))
    h2 = m.hexdigest()
    return binascii.unhexlify(h1 + h2[:8])

def u2f_load_key(master_key, handle, appid, RMASK):
    assert(len(master_key) == 32)
    assert(len(handle) == 36)
    assert(len(RMASK) == 36)
    private_key = hmac_sha256(master_key, appid[:32] + handle[:4])
    assert(len(private_key) == 32)
    private_key = '\x00\x00\x00\x00' + private_key

    return xor_strings(private_key, '\x00\x00\x00\x00'+RMASK[4:] )

def compute_key_hash(key, mask):
    assert(len(mask) == 36)
    assert(len(key) == 36)
    appdata_tmp = '\x46\x40\x02\x00\xee\x01\x23' + '\x00'*21 + key #Steal from u2f-zero 'compute_key_hash' function.
    assert(len(appdata_tmp) == 28+36)
    return sha256(mask[:32]+appdata_tmp)

if __name__ == "__main__":
    # Example, From Serial Port output:
    # master key: 6b58151a51298547011e6076606f0d49a55d3e6298bcfec0a26d8bbc544d328c
    test_master_key = binascii.unhexlify("6b58151a51298547011e6076606f0d49a55d3e6298bcfec0a26d8bbc544d328c")

    #test_handle = websafe_base64_decode("mDAaZyHZFf0Tom2-_Y9DbE5Ef_bI0G_MEZ83m8HpemzvHGNV")  #test case for pam.d
    #test_handle = websafe_base64_decode("1PW37RFF2tj-8EBjqoU9-FopH38RSgP9NUUec7isNhq75ju3")  #alternative test case for pam.d
    test_handle = websafe_base64_decode("cY2BxtmLWzEf8TGAKgoRkUI1oDnkydp1bHVCVD9QSXtiQxN8")  #test case for https://demo.yubico.com

    #test_appid = sha256("pam://scateu-ThinkPad-X230")
    #test_appid = sha256("https://demo.yubico.com")
    test_appid = binascii.unhexlify("a54672b222c4cf95e151ed8d4d3c767a6cc349435943794e884f3d023a8229fd") #Gmail

    test_WMASK = get_write_mask(test_master_key)
    test_RMASK = "\x1a\x1a\x81\x7b\xa8\x0a\x9b\x8f\x23\x08\xbd\xcb\x6c\x1c\xb6\x99\x47\x4a\xe9\xbb\x2c\x67\xbd\x58\x82\x66\xdd\x94\x6b\x66\x06\xd8\xd5\x51\x6c\xc9"

    test_private_key = u2f_load_key(test_master_key, test_handle, test_appid, test_RMASK)
    assert(compute_key_hash(test_private_key,test_WMASK) == test_handle[4:])
    #print("Hooray!")

    print(test_private_key.encode('hex'))
    #sys.stdout.write(test_private_key[4:])
    # example private key output: 1558d8a83b887780930c3ebc13fddc5251428abdeaa032938b18701663117c44

    expected_public_key = "04a4a9c76219b1248e83138b785af813c13e2aedcfca89e9f77a2a60c9dea163195a1b6199f5f9db2c8b2669188ac1b1333424dd3d4992aa3eeb67a62b9ba735ee" #pam.d test case, from pamu2fcfg
    # verify it with  https://kjur.github.io/jsrsasign/sample-ecdsa.html
    # prime256v1 NIST CURVE: P-256

    # TODO 方便地集成 v2f.py
    # TODO 对fastmail做一个测试



#DEMO key handle :
#scateu:mDAaZyHZFf0Tom2-_Y9DbE5Ef_bI0G_MEZ83m8HpemzvHGNV,04a4a9c76219b1248e83138b785af813c13e2aedcfca89e9f77a2a60c9dea163195a1b6199f5f9db2c8b2669188ac1b1333424dd3d4992aa3eeb67a62b9ba735ee

###scateu:1PW37RFF2tj-8EBjqoU9-FopH38RSgP9NUUec7isNhq75ju3,0407f91ce02a5b7d6c4a7da34c01f7a64fd09071ef85ed5ff55a7acb3fd8a8b22c387cd5c8866663f53928e0ecdb7e738682e28232101244f8c820b78ff6afe6ee

###
### DEMO
### Key Handle: mDAaZyHZFf0Tom2-_Y9DbE5Ef_bI0G_MEZ83m8HpemzvHGNV,04a4a9c76219b1248e83138b785af813c13e2aedcfca89e9f77a2a60c9dea163195a1b6199f5f9db2c8b2669188ac1b1333424dd3d4992aa3eeb67a62b9ba735ee
###
#:~$ sudo -s
#[../pam-u2f.c:parse_cfg(48)] called.
#[../pam-u2f.c:parse_cfg(49)] flags 32768 argc 3
#[../pam-u2f.c:parse_cfg(51)] argv[0]=authfile=/etc/u2f_mappings
#[../pam-u2f.c:parse_cfg(51)] argv[1]=cue
#[../pam-u2f.c:parse_cfg(51)] argv[2]=debug
#[../pam-u2f.c:parse_cfg(52)] max_devices=0
#[../pam-u2f.c:parse_cfg(53)] debug=1
#[../pam-u2f.c:parse_cfg(54)] interactive=0
#[../pam-u2f.c:parse_cfg(55)] cue=1
#[../pam-u2f.c:parse_cfg(56)] manual=0
#[../pam-u2f.c:parse_cfg(57)] nouserok=0
#[../pam-u2f.c:parse_cfg(58)] alwaysok=0
#[../pam-u2f.c:parse_cfg(59)] authfile=/etc/u2f_mappings
#[../pam-u2f.c:parse_cfg(60)] origin=(null)
#[../pam-u2f.c:parse_cfg(61)] appid=(null)
#[../pam-u2f.c:pam_sm_authenticate(103)] Origin not specified, using "pam://scateu-ThinkPad-X230"
#[../pam-u2f.c:pam_sm_authenticate(114)] Appid not specified, using the same value of origin (pam://scateu-ThinkPad-X230)
#[../pam-u2f.c:pam_sm_authenticate(124)] Maximum devices number not set. Using default (24)
#[../pam-u2f.c:pam_sm_authenticate(142)] Requesting authentication for user scateu
#[../pam-u2f.c:pam_sm_authenticate(153)] Found user scateu
#[../pam-u2f.c:pam_sm_authenticate(154)] Home directory for scateu is /home/scateu
#[../pam-u2f.c:pam_sm_authenticate(205)] Using authentication file /etc/u2f_mappings
#[../util.c:get_devices_from_authfile(83)] Authorization line: scateu:axh4xfEr6o_i6z8BAXcW24Q_2AWGgfx2HiW7FURLV-Wz-hCPIh_UWS1ANASSUDsxNDklsZsf2tqQ_ECy4KdRmA,04c113c247a2233665f58c1f949f25c91f9408b7dc769e69c844e147fabc6cba73be629f2dc4a8c559aeab72ca24fcd5bce221b29ea5cd0a52131f2426625376d7:mDAaZyHZFf0Tom2-_Y9DbE5Ef_bI0G_MEZ83m8HpemzvHGNV,04a4a9c76219b1248e83138b785af813c13e2aedcfca89e9f77a2a60c9dea163195a1b6199f5f9db2c8b2669188ac1b1333424dd3d4992aa3eeb67a62b9ba735ee
#[../util.c:get_devices_from_authfile(88)] Matched user: scateu
#[../util.c:get_devices_from_authfile(106)] KeyHandle for device number 1: axh4xfEr6o_i6z8BAXcW24Q_2AWGgfx2HiW7FURLV-Wz-hCPIh_UWS1ANASSUDsxNDklsZsf2tqQ_ECy4KdRmA
#[../util.c:get_devices_from_authfile(133)] publicKey for device number 1: 04c113c247a2233665f58c1f949f25c91f9408b7dc769e69c844e147fabc6cba73be629f2dc4a8c559aeab72ca24fcd5bce221b29ea5cd0a52131f2426625376d7
#[../util.c:get_devices_from_authfile(148)] Length of key number 1 is 65
#[../util.c:get_devices_from_authfile(106)] KeyHandle for device number 2: mDAaZyHZFf0Tom2-_Y9DbE5Ef_bI0G_MEZ83m8HpemzvHGNV
#[../util.c:get_devices_from_authfile(133)] publicKey for device number 2: 04a4a9c76219b1248e83138b785af813c13e2aedcfca89e9f77a2a60c9dea163195a1b6199f5f9db2c8b2669188ac1b1333424dd3d4992aa3eeb67a62b9ba735ee
#[../util.c:get_devices_from_authfile(148)] Length of key number 2 is 65
#[../util.c:get_devices_from_authfile(176)] Found 2 device(s) for user scateu
#Please touch the device.
#[../util.c:do_authentication(238)] Device max index is 0
#[../util.c:do_authentication(264)] Attempting authentication with device number 1
#[../util.c:do_authentication(286)] Challenge: { "keyHandle": "axh4xfEr6o_i6z8BAXcW24Q_2AWGgfx2HiW7FURLV-Wz-hCPIh_UWS1ANASSUDsxNDklsZsf2tqQ_ECy4KdRmA", "version": "U2F_V2", "challenge": "bw1fsHLDj84vl2MHrFzNjYEeM5Ygeukt47L1YuSH-LE", "appId": "pam:\/\/scateu-ThinkPad-X230" }
#[../util.c:do_authentication(304)] Unable to communicate to the device, authenticator error
#[../util.c:do_authentication(264)] Attempting authentication with device number 2
#[../util.c:do_authentication(286)] Challenge: { "keyHandle": "mDAaZyHZFf0Tom2-_Y9DbE5Ef_bI0G_MEZ83m8HpemzvHGNV", "version": "U2F_V2", "challenge": "bw1fsHLDj84vl2MHrFzNjYEeM5Ygeukt47L1YuSH-LE", "appId": "pam:\/\/scateu-ThinkPad-X230" }
#[../util.c:do_authentication(292)] Response: { "signatureData": "AQAAACgwRAIgJKmDL6KR-F5zYk7siOAGIJCzSTDzOra4qMuxrONRwoQCIAYt2tPNb4VyXmZYNDQnFTyXanvz5ZBFjRwZdnV9zWXJ", "clientData": "eyAiY2hhbGxlbmdlIjogImJ3MWZzSExEajg0dmwyTUhyRnpOallFZU01WWdldWt0NDdMMVl1U0gtTEUiLCAib3JpZ2luIjogInBhbTpcL1wvc2NhdGV1LVRoaW5rUGFkLVgyMzAiLCAidHlwIjogIm5hdmlnYXRvci5pZC5nZXRBc3NlcnRpb24iIH0", "keyHandle": "mDAaZyHZFf0Tom2-_Y9DbE5Ef_bI0G_MEZ83m8HpemzvHGNV" }
#[../pam-u2f.c:pam_sm_authenticate(259)] done. [Success]
#
