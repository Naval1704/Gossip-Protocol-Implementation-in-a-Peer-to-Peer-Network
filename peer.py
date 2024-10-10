import socket
import json
import threading
import time
import hashlib
import random
import sys

class PeerNode:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connected_seed_ports = []
        self.connected_peer_ports = []
        self.timestamp = int(time.time())
        self.message_counter = 0
        self.message_log = {}
        self.liveness_counter = {}
        self.seed_port_host = []

    def generate_message(self):
        message = f"{self.timestamp}:{self.host}:{self.message_counter}"
        self.message_counter += 1
        return message

    def start_gossip(self):
        gossip_handle_thread = threading.Thread(target=self.gossip_handle)
        gossip_handle_thread.start()
        

        # Continue liveness testing every 13 seconds
        liveness_handle_thread = threading.Thread(target=self.liveness_handle)
        liveness_handle_thread.start()
        # while True:
        #     time.sleep(13)
        #     self.check_liveness()

    def gossip_handle(self):
        while self.message_counter < 10:
            time.sleep(5)
            gossip_message = self.generate_message()
            print(f"Generated Gossip Message: {gossip_message}")

            # Broadcast the gossip message to connected peers
            self.broadcast_gossip_message(gossip_message)

    def liveness_handle(self):
        while True:
            time.sleep(13)
            self.check_liveness()

    def check_liveness(self):
        liveness_request = f"Liveness Request:{self.timestamp}:{self.host}"

        for peer_socket in self.connected_peer_ports:
            try:
                peer_socket.send(liveness_request.encode())
                print(f"Sent liveness request to {peer_socket.getpeername()}")

                # Wait for a reply for 5 seconds
                peer_socket.settimeout(5)
                response_data = peer_socket.recv(1024)
                if response_data:
                    response = response_data.decode('utf-8')
                    if response.startswith("Liveness Reply"):
                        print(f"Received liveness reply from {peer_socket.getpeername()}")
                        self.liveness_counter[peer_socket] = 0
                else:
                    print(f"No liveness reply received from {peer_socket.getpeername()}")
                    self.liveness_counter[peer_socket] += 1

            except Exception as e:
                print(f"Error checking liveness with {peer_socket.getpeername()}: {e}")
                print(self.liveness_counter)
                print("    ")
                self.liveness_counter[peer_socket] += 1

            if self.liveness_counter[peer_socket] >= 3:
                # Notify seed nodes that the peer is not responding
                print("more than 3 times")
                self.notify_seed_node_dead(peer_socket)
                self.liveness_counter[peer_socket]=0
                self.connected_peer_ports.remove(peer_socket)


    
    def notify_seed_node_dead(self, peer_socket):
        for seed in self.seed_port_host:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                try:
                    client_socket.connect((seed[0], seed[1]))
                    # print(client_socket)
                    self.connected_seed_ports.append(client_socket)
                    print(f"peer to be removed : host: {peer_socket.getpeername()[0]} port: {peer_socket.getpeername()[1]}")
                    message = {'type': 'remove_peers', 'host': peer_socket.getpeername()[0], 'port': peer_socket.getpeername()[1]}
                    client_socket.sendall(json.dumps(message).encode('utf-8'))
                except Exception as e:
                    print(f"Failed to connect to Seed Node {seed}: {e}") 
    def handle_client(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode()
                if not message:
                    break

                print(f"Received from client: {message}")

                # Check if it's a liveness request
                if message.startswith("Liveness Request"):
                    self.handle_liveness_request(message, client_socket)
                    continue

                # Check if it's a gossip message
                if self.process_gossip_message(message):
                    continue

                response = input("Enter your response: ")
                client_socket.send(response.encode())

            except ConnectionResetError:
                print("Client disconnected.")
                break

        # client_socket.close()

    def receive_messages(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode()
                print(f"Received from server: {message}")

                # Check if it's a liveness request
                if message.startswith("Liveness Request"):
                    self.handle_liveness_request(message, client_socket)
                    continue

                # Check if it's a gossip message
                self.process_gossip_message(message)

            except ConnectionResetError:
                print("Server disconnected.")
                break

        # client_socket.close()

    def handle_liveness_request(self, request, sender_socket):
        _, sender_timestamp, sender_ip = request.split(':')
        liveness_reply = f"Liveness Reply:{sender_timestamp}:{sender_ip}:{self.host}"

        try:
            sender_socket.send(liveness_reply.encode())
            print(f"Sent liveness reply to {sender_socket.getpeername()}")
        except Exception as e:
            print(f"Error sending liveness reply to {sender_socket.getpeername()}: {e}")

    def process_gossip_message(self, message):
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        if message_hash in self.message_log:
            return False

        self.message_log[message_hash] = True
        print(f"Received new Gossip Message: {message}")
        with open("output.txt","a") as file:
            file.write(f"Received Gossip Message: {message} from {message.split(':')[1]} at {self.timestamp}\n")

        self.broadcast_gossip_message(message)

        return True

    def broadcast_gossip_message(self, gossip_message):
        for peer_socket in self.connected_peer_ports:
            try:
                peer_socket.send(gossip_message.encode())
            except Exception as e:
                print(f"Failed to broadcast gossip message to {peer_socket}: {e}")

    def connect_to_peer(self, peer):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((peer[0], peer[1]))
        print(f"Connected to peer: {peer[0]}:{peer[1]}")

        self.connected_peer_ports.append(client_socket)
        self.liveness_counter[client_socket] = 0

        receive_thread = threading.Thread(target=self.receive_messages, args=(client_socket,))
        receive_thread.start()
       

    def start(self):
        # file = open("D:\IIT Jodhpur\Third Year\SEMESTER 6\COMPUTER NETWORKS\Assignment1\config.json")
        # seed_nodes = json.load(file)
        # self.connected_seed_ports=seed_nodes
        with open("config.txt", "r") as file:
            lines = file.readlines()
            seed_nodes = []
            for line in lines:
                data = line.strip().split()
                data_dict = {'host': data[0], 'port': int(data[1])}
                seed_nodes.append(data_dict)

        num_seed_nodes_to_connect = len(seed_nodes)
        peer_list = self.get_peers_from_seed_nodes(seed_nodes, num_seed_nodes_to_connect)

        # Take a union of all peer lists received from different seeds

        # Convert each sublist to a tuple to make it hashable
        unique_peer_set = set(tuple(peer) for peer in peer_list)

        # Convert the unique tuples back to lists
        unique_peer_list = [list(peer) for peer in unique_peer_set]

        # Randomly select a maximum of 4 distinct peer nodes
        selected_peers = random.sample(peer_list, min(4, len(peer_list)))

        selected_peer_list = unique_peer_list[:min(4, len(unique_peer_list))]

        print("Selected Peer List:", selected_peer_list)

        # Establish TCP connections with selected peers
        for peer in selected_peer_list:
            if (self.port!=peer[1]):
                self.connect_to_peer(peer)
             

      
        start_gossip_thread = threading.Thread(target=self.start_gossip)
        start_gossip_thread.start()

    def get_peers_from_seed_nodes(self, seed_nodes, num_seed_nodes_to_connect):
        selected_seed_nodes = random.sample(seed_nodes, num_seed_nodes_to_connect)
        connected_sockets = []
        all_peer_lists = []

        for seed_node in selected_seed_nodes:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                try:
                    client_socket.connect((seed_node['host'], seed_node['port']))
                    self.connected_seed_ports.append(client_socket)
                    self.seed_port_host.append((seed_node['host'], seed_node['port']))
                    message = {'type': 'get_peers', 'host': self.host, 'port': self.port}
                    client_socket.sendall(json.dumps(message).encode('utf-8'))

                    response_data = client_socket.recv(1024)
                    if response_data:
                        response = json.loads(response_data.decode('utf-8'))
                        if response['type'] == 'peers':
                            peer_list = response['peers']
                            print(f"Received peer list from Seed Node {seed_node['host']}:{seed_node['port']}:", peer_list)
                            all_peer_lists.extend(peer_list)
                except Exception as e:
                    print(f"Failed to connect to Seed Node {seed_node['host']}:{seed_node['port']}: {e}")

            connected_sockets.append(client_socket)

        # for connected_socket in connected_sockets:
        #     connected_socket.close()

        if all_peer_lists:
            print("Successfully received peer lists from all connected seed nodes.")
            return all_peer_lists
        else:
            print("Failed to get peer lists from any seed node.")
            return []

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    peer = PeerNode(host, port)
    peer.start()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("Server listening on port ..")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")

        client_handler = threading.Thread(target=peer.handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    main()
