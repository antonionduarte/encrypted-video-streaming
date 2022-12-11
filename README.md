# Video-Stream Ciphering
Repository for the Stream Ciphering Project of the Network Security Course @ FCT-UNL.

# Environment Variables
- `CRYPTO_CONFIG_KEY`: The key to the AES key for the video sharing. **DEPRECATED**,
- `CA_PASSWORD`: The password of the CA Keystore.
- `BOX_PASSWORD`: The password of the Box Keystore.
- `SERVER_PASSWORD`: The password of the Server Keystore.

# How To Compile

We're using maven to compile the project. To compile the project, run the following command:
```
mvn clean compile assembly:single
```
It's important that you use `assembly:single` instead of `package` because the latter will not include the dependencies in the final jar file.

# How to Run
There are two alternatives to running this project, in both of the alternatives you firstly need to export the 
AES key to decrypt the movies. To do so, run the following command:

```bash
export CRYPTO_CONFIG_KEY = <your key>
```

If you want to use the already ciphered movies:

```bash
export CRYPTO_CONFIG_KEY = "aaaaaaaabbbbbbbbccccccccdddddddd"
```

### Docker compose

The docker compose alternative runs two containers, one for the server and one for the proxy.
In order for the Host to be able to receive UDP packets from the proxy container, the containers run in `network_mode=host`.
Given that this network mode is not available in macOS, **this alternative only works in a Linux environment**.

To run the project using docker compose, run the following command:

```bash 
docker compose build
docker compose up
```

Or alternatively you could run the following script from the root project dir, that automatically compiles 
and runs the project:

```bash
./scripts/build-and-deploy.sh
```
If docker doesn't have compose command built-in, use `docker-compose` instead.


**Note:** by default the docker version will run the movie `cars.dat.enc`. If you wish to run another one you must change it in
the `docker/server/Dockerfile` file.
You can do so by changing the line:

```Dockerfile
CMD java -cp ciphered-video-server.jar Server movies/ciphered/<movie-you-want-to-watch>
```

### Locally

To run it locally, you need to compile the project and simply run, for the **Proxy**:
```bash
java -cp target/ciphered-video-server.jar Proxy 
```

And for the server:
```bash
java -cp target/ciphered-video-server.jar Server <encrypted-movie-filename>
```

# Configuration 

There are two types of configuration files, the ones present in the `movies` directory and the ones in the `config` directory.
There are two JSON files, and one properties file in `config/proxy/config.properties`.

### Movies Cipher Suite

In the `movies` directory, we have a folder which contains everything already encrypted. 
If you want to see the plaintext version of the movies and the configuration file you can see it in
`movies/plain/`.

The `movies/plain/cryptoconfig.json` contains the ciphersuites used to encrypt the movies and to verify their integrity.

```json
{
  "cars.dat.enc": {
    "cipher": "AES/CBC/PKCS5Padding",
    "key": "91342609ae5435f69a23652476e67abc",
    "iv": "4524568176123498",
    "integrity": "SHA256",
    "integrity-check": "9123496ab52311a4762a3efe110176233abff246ab52311a4762a3efe1101762"
  },
  "monsters.dat.enc": {
    "cipher": "RC6/CTR/NoPadding",
    "key": "476e67a34e5571897612391bcce24512",
    "iv": "8a451982e562c487",
    "integrity": "HMAC-SHA1",
    "integrity-check": "997612567254197629aa4512761691c156a19920",
    "mackey": "6af53417a7f5e4321a65a31213048567"
  }
} 
```

Each map entry starts with the name of the encrypted movie file, and then inside the cipher suite.
Instead of writing something like `NULL` for the non-present fields in a cipher suite, we decided to omit them. The parser (Google's GSON) will
correctly detect that they're not present.

### Stream Cipher Suite

The `config/box-cryptoconfig.json` contains the configuration file for the cipher suite to be used between the 
stream server and the proxy.

```json
{
  "127.0.0.1:9999": {
    "cipher": "AES/CBC/PKCS5Padding",
    "key": "91342609ae5435f69a23652476e67abc",
    "iv": "4524568176123498",
    "integrity": "SHA256"
  }
}
```

The map entry starts with the IP and port of the proxy, and then the cipher suite.

### Box Properties

The box properties are contained in `config/proxy/config.properties` and are used to configure the proxy.

```properties
remote=127.0.0.1:9999
localdelivery=127.0.0.1:7575
```
