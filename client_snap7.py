import snap7

client = snap7.client.Client()
client.connect('127.0.0.1', 0, 1, 102)

if client.get_connected():
    print("[Snap7] Connecté au serveur PLC.")
    data = client.db_read(1, 0, 10)
    print(f"[Snap7] Données lues : {data}")
    client.disconnect()
    print("[Snap7] Déconnecté.")
else:
    print("[Snap7] Échec de la connexion.")
