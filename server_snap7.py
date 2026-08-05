import ctypes
import time
import snap7
from snap7.type import SrvArea

server = snap7.server.Server()
size = 100
DB1 = (ctypes.c_ubyte * size)()
server.register_area(SrvArea.DB, 1, DB1)
server.start(tcp_port=102)
print("Serveur Snap7 démarré sur le port 102...")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    server.stop()
    print("Serveur arrêté.")
