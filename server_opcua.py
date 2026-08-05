from opcua import Server
import time

server = Server()
server.set_endpoint("opc.tcp://0.0.0.0:4840/freeopcua/server/")
uri = "http://examples.freeopcua.github.io"
idx = server.register_namespace(uri)
objects = server.get_objects_node()
myvar = objects.add_variable(idx, "Temperature", 23.5)
myvar.set_writable()

server.start()
print("Serveur OPC UA démarré sur opc.tcp://0.0.0.0:4840...")
print(f"Namespace index utilisé : {idx}")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    server.stop()
    print("Serveur arrêté.")
