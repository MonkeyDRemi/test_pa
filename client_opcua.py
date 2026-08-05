from opcua import Client

url = "opc.tcp://127.0.0.1:4840/freeopcua/server/"
client = Client(url)

try:
    client.connect()
    print("[OPC UA] Connecté au serveur.")
    
    root = client.get_root_node()
    var = root.get_child(["0:Objects", "2:Temperature"])
    value = var.get_value()
    print(f"[OPC UA] Valeur de Temperature : {value}")
    
finally:
    client.disconnect()
    print("[OPC UA] Déconnecté.")
