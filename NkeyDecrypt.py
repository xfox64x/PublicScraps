# NkeyDecrypt.py
# Some shitty "encryption" algo found somewhere.

import base64

Base64ObfuscatedValue = ''
ENCRYPTION_KEY = b''

def nkey(EncryptionKey):
    DlRegister = 0
    EaxRegister = 0
    for BinaryCharacter in EncryptionKey:
        DlRegister += BinaryCharacter
        DlRegister = DlRegister % 256
        #print('{0:X}: {1:X}'.format(EaxRegister, DlRegister))
        EaxRegister+=1
    return DlRegister
    
def decrypt(EncryptedBase64, EncryptionKey):
    keyValue = nkey(EncryptionKey)
    DeobfuscatedValue = ''
    for ByteObj in base64.b64decode(Base64ObfuscatedValue):
        DeobfuscatedValue += (chr(255 & ((255 ^ ByteObj) ^ keyValue)))
    return DeobfuscatedValue

def encrypt(PlaintextPassword, EncryptionKey):
    keyValue = nkey(EncryptionKey)
    ObfuscatedValue = b''
    for ByteObj in PlaintextPassword.encode():
        y = (255 & ((keyValue ^ ByteObj) ^ 255))
        ObfuscatedValue += bytes([y])
    return base64.b64encode(ObfuscatedValue)
    
print('\r\nNkey: {0}'.format(nkey(ENCRYPTION_KEY)))
print('\r\nDeobfuscated Password:\r\n\t{0}'.format(decrypt(Base64ObfuscatedValue, ENCRYPTION_KEY)))
