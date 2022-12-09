#input: alg key_size
#ex: RSA 2048

config_folder="../config/"
box_config_folder=$config_folder"box/"
server_config_folder=$config_folder"server/"
ca_config_folder=$config_folder"ca/"
common_config_folder=$config_folder"common/"
certs_folder="certs/"
csr_folder="csr/"
ca_password="aaaaaaaabbbbbbbbccccccccdddddddd"
box_password="aaaaaaaabbbbbbbbccccccccdddddddd"
server_password="aaaaaaaabbbbbbbbccccccccdddddddd"

alg=$(echo $1 | tr 'a-z' 'A-Z')
key_size=$2
ca_alias="CA_"$alg"_"$key_size
box_alias="box_"$alg"_"$key_size
server_alias="server_"$alg"_"$key_size
ca_ks=$ca_config_folder"ca.pkcs12"
ca_cert=$common_config_folder"ca_root.cer"
box_ks=$box_config_folder"box.pkcs12"
box_cert=$box_config_folder$certs_folder$box_alias".cer"
box_csr=$box_config_folder$csr_folder$box_alias".csr"
server_ks=$server_config_folder"server.pkcs12"
server_cert=$server_config_folder$certs_folder$server_alias".cer"
server_csr=$server_config_folder$csr_folder$server_alias".csr"

#To begin, we first generate a key pair which will be used as the CA,
 #ts private key will be used to sign the certificate it issues.
keytool -genkeypair -noprompt \
  -dname "CN=CA" \
  -keysize $key_size \
  -keyalg $alg \
  -storetype PKCS12 \
  -alias $ca_alias \
  -keystore $ca_ks \
  -storepass $ca_password \
  -ext bc=ca:true

#Generate CA root certificate
keytool -gencert -noprompt \
  -keystore $ca_ks \
  -storepass $ca_password \
  -storetype PKCS12 \aaaaaaaabbbbbbbbccccccccdddddddd
  -alias $ca_alias \
  -outfile $ca_cert

#Then, generate a key pair where the certificate of it will be signed by the CA above.
keytool -genkeypair -noprompt \
  -dname "CN=Box" \
  -keysize $key_size \
  -keyalg $alg \
  -storetype PKCS12 \
  -alias $box_alias \
  -keystore $box_ks \
  -storepass $box_password
keytool -genkeypair -noprompt \
  -dname "CN=Server" \
  -keysize $key_size \
  -keyalg $alg \
  -storetype PKCS12 \
  -alias $server_alias \
  -keystore $server_ks \
  -storepass $server_password

#Next, a certificate request for the "CN=Leaf" certificate needs to be created.
keytool -certreq -noprompt \
  -keystore $server_ks \
  -storepass $server_password \
  -storetype PKCS12 \
  -alias $server_alias \
  -file $server_csr
keytool -certreq -noprompt \
  -keystore $box_ks \
  -storepass $box_password \
  -storetype PKCS12 \
  -alias $box_alias \
  -file $box_csr

#Now creating the certificate with the certificate request generated above.
keytool -gencert -noprompt \
  -keystore $ca_ks \
  -storepass $ca_password \
  -storetype PKCS12 \
  -alias $box_alias \
  -infile $box_csr \
  -outfile $box_cert
keytool -gencert -noprompt \
  -keystore $ca_ks \
  -storepass $ca_password \
  -storetype PKCS12 \
  -alias $server_alias \
  -infile $server_csr \
  -outfile $server_cert

# An output certificate file leaf.cer will be created. Now let's see what its content is.
keytool -printcert -file $ca_cert
keytool -printcert -file $box_cert
keytool -printcert -file $server_cert

