import os, sys
import base64
from OpenSSL import crypto

bundle = sys.argv[1]

os.system("clear")

decoded_bundle = base64.b64decode(bundle).decode()

certificate, privatekey = decoded_bundle.split("-----END CERTIFICATE-----\r\n")
certificate += "-----END CERTIFICATE-----\r\n"

certificate_obj = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
privatekey_obj = crypto.load_privatekey(crypto.FILETYPE_PEM, privatekey)
p12 = crypto.PKCS12()
p12.set_certificate(certificate_obj)
p12.set_privatekey(privatekey_obj)
pkcs12 = base64.b64encode(p12.export()).decode()

print("PKCS12 bundle below, ready to import into rubeus...\n\n")
print(pkcs12)