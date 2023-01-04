# Video-Stream Ciphering
Repository for the Stream Ciphering Project of the Network Security Course @ FCT-UNL.

## How To Compile

We're using maven to compile the project. To compile the project, run the following command:
```
mvn clean compile assembly:single
```
It's important that you use `assembly:single` instead of `package` because the latter will not include the dependencies in the final jar file.

## How to Run
There are two alternatives to running this project, in both of the alternatives you firstly need to export the necessary passwords as environment variables. All of these passwords are in the Environment Variables section of this document.

```bash
export CRYPTO_CONFIG_KEY = <your key>
export CA_PASSWORD = <your password>
export PROXY_PASSWORD = <your password>
export SERVER_PASSWORD = <your password>
export TRUSTSTORE_PASSWORD = <your password>
```

If you want to use the already ciphered movies and the pre-configured certificates, you can run the following commands:

```bash
export CRYPTO_CONFIG_KEY = "aaaaaaaabbbbbbbbccccccccdddddddd"
export CA_PASSWORD = "aaaaaaaabbbbbbbbccccccccdddddddd"
export PROXY_PASSWORD = "aaaaaaaabbbbbbbbccccccccdddddddd"
export SERVER_PASSWORD = "aaaaaaaabbbbbbbbccccccccdddddddd"
export TRUSTSTORE_PASSWORD = "aaaaaaaabbbbbbbbccccccccdddddddd"
```

## Environment Variables

- `CRYPTO_CONFIG_KEY`: The key to the AES key for the video sharing.
- `CA_PASSWORD`: The password of the CA Keystore.
- `PROXY_PASSWORD`: The password of the Proxy Keystore.
- `SERVER_PASSWORD`: The password of the Server Keystore.
- `TRUSTSTORE_PASSWORD`: The password of the Truststore.

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
java -cp target/ciphered-video-server.jar Proxy <movie name>
```

And for the server:
```bash
java -cp target/ciphered-video-server.jar Server
```

## Configuration

### Asymmetric Cryptography Configuration

This configuration refers to the asymmetric cryptographic methods used in the initial handshake process between the proxy and the server.

For the **proxy**, you can find it in the ```config/proxy/asymmetric-config.json``` file.

```json
[
  {
    "authentication": "EC",
    "key-size": 256,
    "key-exchange": "ECDH",
    "num-size": 256
  },
  {
    "authentication": "DSA",
    "key-size": 2048,
    "key-exchange": "ECDH",
    "num-size": 256
  }
]
```

The proxy uses an optimistic approach, meaning that it will try to use the first configuration in the list.

As for the **server**, the configuration is present in the `config/server/asymmetric-config.json`. It also uses a list in the same format, but in the case of the server, should be ordered by order of preference. During the handshake, the server chooses the first cipher suite that matches the one sent by the proxy.

### Symmetric Cryptography Configuration

The symmetric cryptography constructions are the ones used by the protocol after the initial handshake, to encrypt and send the movie frames.

They are present in ````config/proxy/symmetric-config.json```` and ```config/server/symmetric-config.json```. These are sent by the proxy as a list, and should be ordered both in the server and proxy side in order of preference. During the handshake, the server selects the first matching cipher suite.

```json
[
  {
    "cipher": "AES/CBC/PKCS5Padding",
    "key-size": 256,
    "integrity": "DES",
    "mac-key-size": 64,
    "iv-size": 128
  },
  {
    "cipher": "AES/CTR/PKCS5Padding",
    "key-size": 128,
    "integrity": "HMAC-SHA256",
    "mac-key-size": 256,
    "iv-size": 128
  }
]
```

### Handshake Integrity - Pre-Shared Mac Key

The only pre-shared configuration. It is used exclusively for the integrity verification of the handshake messages.
It's present in `config/common/handshake-integrity.json`, and has the following format:

```json
{
  "algorithm": "HMAC-SHA256",
  "mac-key" : "b0a9b9f2b19d738d542c1e879b6d4b7a"
}
```

### Ciphered Movies

The movies are initially stored ciphered, and must be deciphered on Server startup, before being sent. The cipher suites used to cipher the movies are contained in `config/movies/plain/cryptoconfig.json`.
The key used to decipher this cipher suite should be contained in the `CRYPTO_CONFIG_KEY` environment variable.

### Proxy Properties

The proxy properties are contained in `config/proxy/config.properties` and are used to configure the proxy.

```properties
remote=127.0.0.1:9999
localdelivery=127.0.0.1:7575
```

## Helper Scripts

We provide several helper bash scripts to perform different functions, they're all in the `scripts` directory.

- `deploy-docker-compose.sh`: Deploys the project using Docker Compose.
- `setup-movies.sh`: Runs two different scripts to encrypt the movies and generate the necessary cipher suite config file.
- `gen-authentication-files.sh`: Generates certificates for server, proxy and a root CA.
- `deploy-local-parallel.py`: A script to deploy the project locally, in parallel. It's used to test the project locally. The output is displayed in a single terminal instance, so it's a bit more confusing.
- `deploy-local.sh`: It deploys the project locally but generates two separate terminal instances, one for the proxy and one for the server. It's easier to read the output.

**NOTE:** the file paths in the project changed quite a lot during development, some of the scripts might therefore not work without changes right now, particularly `encrypt-config.sh` and `encrypt-movies.sh`.
