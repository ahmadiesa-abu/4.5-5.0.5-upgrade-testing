sudo openssl req -newkey rsa:2048 -nodes -batch -sha256 -config $1.conf -out $1.crt.csr -keyout $1_key.pem
sudo openssl x509 -days 3650 -sha256 -req -in $1.crt.csr -out $1_crt.pem -extensions v3_ext -extfile $1.conf -CA $2 -CAkey $3 -CAcreateserial