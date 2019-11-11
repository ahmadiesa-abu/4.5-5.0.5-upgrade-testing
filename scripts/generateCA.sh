openssl genrsa -out ca_key.pem 2048
touch openssl.cnf

cat >> openssl.cnf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = IL
ST = Hayifa
L = Nablus
O = Cloudify
OU = IT
CN = Cloudify
emailAddress = ahmad@cloudify.co
EOF

openssl req -x509 -config openssl.cnf -new -key ca_key.pem -days 3650 -out ca_crt.pem