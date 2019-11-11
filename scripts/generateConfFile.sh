echo "[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ext
[ req_distinguished_name ]
commonName = _common_name # ignored, _default is used instead
commonName_default = $1
[ v3_ext ]
basicConstraints=CA:false
authorityKeyIdentifier=keyid:true
subjectKeyIdentifier=hash
subjectAltName=DNS:$1,DNS:127.0.0.1,DNS:$2,DNS:localhost,IP:127.0.0.1,IP:$2" > $1.conf