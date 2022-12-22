# input: alg key_size
# example: RSA 2048
# example: DSA 2048
# example: EC 256

config_folder="certs/"
proxy_config_folder=$config_folder"proxy/"
server_config_folder=$config_folder"server/"
ca_config_folder=$config_folder"ca/"
common_config_folder=$config_folder"common/"
certs_folder="certs/"
csr_folder="cert_requests/"

mkdir $config_folder &> /dev/null
mkdir $proxy_config_folder &> /dev/null
mkdir $server_config_folder &> /dev/null
mkdir $ca_config_folder &> /dev/null
mkdir $ca_config_folder$certs_folder &> /dev/null
mkdir $common_config_folder &> /dev/null
mkdir $proxy_config_folder$certs_folder &> /dev/null
mkdir $server_config_folder$certs_folder &> /dev/null
mkdir $common_config_folder &> /dev/null
mkdir $proxy_config_folder$csr_folder &> /dev/null
mkdir $server_config_folder$csr_folder &> /dev/null

alg=$(echo $1 | tr 'a-z' 'A-Z')
key_size=$2
ca_alias="ca_"$alg"_"$key_size
proxy_alias="proxy_"$alg"_"$key_size
server_alias="server_"$alg"_"$key_size
ca_ks=$ca_config_folder"ca.pkcs12"
ca_cert=$ca_config_folder$certs_folder$ca_alias".cer"
proxy_ks=$proxy_config_folder"proxy.pkcs12"
proxy_cert=$proxy_config_folder$certs_folder$proxy_alias".cer"
proxy_csr=$proxy_config_folder$csr_folder$proxy_alias".csr"
server_ks=$server_config_folder"server.pkcs12"
server_cert=$server_config_folder$certs_folder$server_alias".cer"
server_csr=$server_config_folder$csr_folder$server_alias".csr"
truststore=$common_config_folder"truststore.pkcs12"

# To begin, we first generate a key pair which will be used as the CA,
# its private key will be used to sign the certificate it issues.
keytool -genkeypair -noprompt \
  -dname "CN=CA" \
  -keysize $key_size \
  -keyalg $alg \
  -storetype PKCS12 \
  -alias $ca_alias \
  -keystore $ca_ks \
  -storepass $CA_PASSWORD \
  -ext bc=ca:true

# Generate CA root certificate
keytool -export -noprompt \
  -alias $ca_alias \
  -storepass $CA_PASSWORD \
  -storetype PKCS12 \
  -file $ca_cert \
  -keystore $ca_ks

keytool -import -noprompt \
  -alias $ca_alias \
  -file $ca_cert \
  -storetype PKCS12 \
  -storepass $TRUSTSTORE_PASSWORD \
  -keystore $truststore


# Then, generate a key pair where the certificate of it will be signed by the CA above.
keytool -genkeypair -noprompt \
  -dname "CN=Proxy" \
  -keysize $key_size \
  -keyalg $alg \
  -storetype PKCS12 \
  -alias $proxy_alias \
  -keystore $proxy_ks \
  -storepass $PROXY_PASSWORD
keytool -genkeypair -noprompt \
  -dname "CN=Server" \
  -keysize $key_size \
  -keyalg $alg \
  -storetype PKCS12 \
  -alias $server_alias \
  -keystore $server_ks \
  -storepass $SERVER_PASSWORD

# Next, a certificate request for the "CN=Leaf" certificate needs to be created.
keytool -certreq -noprompt \
  -keystore $proxy_ks \
  -storepass $PROXY_PASSWORD \
  -storetype PKCS12 \
  -alias $proxy_alias \
  -file $proxy_csr
keytool -certreq -noprompt \
  -keystore $server_ks \
  -storepass $SERVER_PASSWORD \
  -storetype PKCS12 \
  -alias $server_alias \
  -file $server_csr


# Now creating the certificate with the certificate request generated above.
keytool -gencert -noprompt \
  -keystore $ca_ks \
  -storepass $CA_PASSWORD \
  -storetype PKCS12 \
  -alias $ca_alias \
  -infile $proxy_csr \
  -outfile $proxy_cert
keytool -gencert -noprompt \
  -keystore $ca_ks \
  -storepass $CA_PASSWORD \
  -storetype PKCS12 \
  -alias $ca_alias \
  -infile $server_csr \
  -outfile $server_cert

# An output certificate file leaf.cer will be created. Now let's see what its content is.
keytool -printcert -file $ca_cert
keytool -printcert -file $proxy_cert
keytool -printcert -file $server_cert

# list truststore
keytool -list \
  -keystore $truststore \
  -storepass $TRUSTSTORE_PASSWORD

