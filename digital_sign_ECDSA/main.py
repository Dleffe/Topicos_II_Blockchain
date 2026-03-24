import sys

from ecdsa import SigningKey,  VerifyingKey, BadSignatureError, SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der

import base64
from hashlib import sha256



if __name__ == "__main__":

    command = sys.argv[1]

    if command == "keygen":
        priv_key_file = sys.argv[2]
        pub_key_file = sys.argv[3]

        priv_key = SigningKey.generate(curve=SECP256k1)
        pub_key = priv_key.verifying_key

        priv_key_der = priv_key.to_der()
        pub_key_der = pub_key.to_der()

        priv_key_b64 = base64.b64encode(priv_key_der)
        pub_key_b64 = base64.b64encode(pub_key_der)

        with open(priv_key_file, "wb") as f:
            f.write(priv_key_b64)
            
        with open(pub_key_file, "wb") as f:
            f.write(pub_key_b64)
        
        print("CHAVES GERADAS")

    elif command == "sign":
        priv_key_file = sys.argv[2]
        file_to_sign = sys.argv[3]
        sig_file = sys.argv[4]

        with open(priv_key_file, "rb") as f:
            der_priv_key = base64.b64decode(f.read())
            priv_key = SigningKey.from_der(der_priv_key)

        with open(file_to_sign, "rb") as f:
            sig = priv_key.sign_deterministic(f.read(), hashfunc=sha256, sigencode=sigencode_der)
        
        with open(sig_file, "wb") as f:
            f.write(sig)

        print("ARQUIVO ASSINADO")

    elif command == "verify":

        pub_key_file = sys.argv[2]
        file_signed = sys.argv[3]
        sig_file = sys.argv[4]

        with open(pub_key_file) as f:
            der_pub_key = base64.b64decode(f.read())
            pub_key = VerifyingKey.from_der(der_pub_key)

        with open(file_signed, "rb") as f:
            msg = f.read()

        with open(sig_file, "rb") as f:
            sig = f.read()


        try:
            ret = pub_key.verify(sig, msg, sha256, sigdecode=sigdecode_der)
            assert ret
            print("Valid signature")
        except BadSignatureError:
            print("Incorrect signature")



    else:
        print("Please use an valid command [ keygen, sign or verify ]")
        sys.exit(-1)
