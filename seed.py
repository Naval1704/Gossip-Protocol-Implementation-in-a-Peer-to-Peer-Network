import socket
import threading
import json

class SeedNode:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = []
        self.lock = threading.Lock()
        self.start()

    def start(self):
        server_thread = threading.Thread(target=self.start_server)
        server_thread.start()

 

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            try:
                server_socket.bind((self.host, self.port))
            except OSError as e:
                print(f"Error: Unable to bind to {self.host}:{self.port}. Port may be in use. {e}")
                return

            server_socket.listen()
            print(f"Seed Node listening on {self.host}:{self.port}")

            while True:
                try:
                    client_socket, address = server_socket.accept()
                    print(f"Connection established with {address}")

                    # Handle the connection in a new thread
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                    client_thread.start()
                except ConnectionResetError:
                    print("Connection reset by peer")

   
    def handle_client(self, client_socket):
        with client_socket:
            try:
                data = client_socket.recv(1024)
                if not data:
                    return

                message = json.loads(data.decode('utf-8'))

               
                print(message)  

                if message['type'] == 'get_peers':
                    response = {'type': 'peers', 'peers': self.peers}
                    client_socket.sendall(json.dumps(response).encode('utf-8'))
                    print(f"Sent peer list to {message['host']}:{message['port']}")

                    self.add_peer(message['host'], message['port'])
                    print(f"Registered new peer: {message['host']}:{message['port']}")
                
                elif message['type']=='remove_peers':
                # elif message.startswith("Dead Node"):
                #     host = message.split(":")[1]
                #     port = int(message.split(":")[2])
                #     l = (host, port)
                    l=(message['host'],message['port'])
                    print(f"will be Removing peer: {l}")
                    print(f"Peers: {self.peers}")
                    if (l in self.peers):
                        self.peers.remove(l)
                        print(f"Removed peer: {l}")
                        print(f"Peers after removing: {self.peers}")

            except Exception as e:
                print(f"Error handling client: {e}")

    def add_peer(self, host, port):
        with self.lock:
            if (host, port) not in self.peers:
                self.peers.append((host, port))




    def get_peers(self):
        with self.lock:
            return self.peers
    
def start_seed(host, port):
    seed_node = SeedNode(host, port)    
    
def main():

    # seed_nodes = json.load(f)
    with open("config.txt", "r") as f:
        lines = f.readlines()
        for line in lines:
            data = line.strip().split()
            seed_node = SeedNode(data[0], int(data[1]))
    # for data in seed_nodes:
    #     # seed_thread = threading.Thread(target=start_seed, args=(data['host'], data['port']))
    #     # seed_thread.start()
    #     seed_node = SeedNode(data['host'], data['port'])
    #     # seed_node.start()


if __name__ == "__main__":
    main()

