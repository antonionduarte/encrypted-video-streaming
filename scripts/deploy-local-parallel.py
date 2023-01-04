import sys
from subprocess import Popen
import time

DEPLOY_SERVER = "java -cp target/ciphered-video-server.jar Server"

def deploy_proxy(movieName: str):
    cmd = [
        "java",
        "-cp", 
        "target/ciphered-video-server.jar",
        "Proxy",
        f"{movieName}"
    ]
    Popen(cmd)

def deploy_server():
    cmd = [
        "java",
        "-cp",
        "target/ciphered-video-server.jar",
        "Server"
    ]
    Popen(cmd)

if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print("Correct usage: ./deploy-local-non-retarded-way.py <movie name>")

    deploy_server()
    print("Sleeping for 3 seconds to wait for Server to init...")
    time.sleep(3)
    deploy_proxy(sys.argv[1])
