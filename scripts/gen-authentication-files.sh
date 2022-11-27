#input: alg key_size
#ex: RSA 2048

config_folder="../config/"
proxy_config_folder=$config_folder"proxy/"
server_config_folder=$config_folder"server/"
common_config_folder=$config_folder"common/"
certs_folder="certs/"
password="aaaaaaaabbbbbbbbccccccccdddddddd"

alg=$(echo $1 | tr 'a-z' 'A-Z')
key_size=$2
proxy_alias="proxy_"$alg"_"$key_size
server_alias="server_"$alg"_"$key_size
proxy_ks=$proxy_config_folder"proxy.pkcs12"
proxy_cert=$proxy_config_folder$certs_folder$proxy_alias".cer"
server_ks=$server_config_folder"server.pkcs12"
server_cert=$server_config_folder$certs_folder$server_alias".cer"
trustedstore=$common_config_folder"trustedstore"

#Generate key pair for proxy and server
keytool -genkeypair -noprompt \
  -dname "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, S=Unknown, C=Unknown" \
  -keysize $key_size \
  -keyalg $alg \
  -storetype PKCS12 \
  -alias $proxy_alias \
  -keystore $proxy_ks \
  -storepass $password
keytool -genkeypair -noprompt \
  -dname "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, S=Unknown, C=Unknown" \
  -keysize $key_size \
  -keyalg $alg \
  -storetype PKCS12 \
  -alias $server_alias \
  -keystore $server_ks \
  -storepass $password

#Generate certificates for proxy and server
keytool -export \
  -alias $proxy_alias \
  -keystore $proxy_ks \
  -file $proxy_cert <<< $password
keytool -export \
  -alias $server_alias \
  -keystore $server_ks \
  -file $server_cert <<< $password

#Insert certificates in trustedstore (CA)
keytool -import -noprompt \
  -storetype PKCS12 \
  -file $proxy_cert \
  -alias $proxy_alias \
  -keystore $trustedstore <<< $password
keytool -import -noprompt \
  -storetype PKCS12 \
  -file $server_cert \
  -alias $server_alias \
  -keystore $trustedstore <<< $password

#List trustedstore
keytool -list -noprompt -v -keystore $trustedstore <<< $password


