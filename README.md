# Peer to Peer Gossip Protocol

This is a simple implementation of a peer to peer gossip protocol for broadcasting messages and checking the liveness of connected peers.
The protocol is implemented in `Python` and uses the `socket` library for communication between peers with the help of threads using the `threading` library.

## Description

- ### File Structure
    - `seed.py` - The file contains the code for the seed node.
    - `peer.py` - The file contains the code for the peer node.
    - `config.txt` - The file contains the ip address and the port of the seed nodes.
    - `output.txt` - The file contains the details of the gossip messages received by the peer nodes.
    - `README.md` - The file contains the description of the project and the instructions to run the code.

The `seed.py` file is used to get the seed nodes up and running on different threads. It loads the ip address and the port of the seed nodes from the `config.txt` file and starts listening for incomming connections.

The peer nodes can be started using the `peer.py`file. Multiple peers can be started by running this file in different terminals. The peer nodes are started by providing the ip address and the port of the seed node as command line arguments.


## Installation

- #### Start the seed nodes by running the following command in the terminal
```bash
    python seed.py
```

- #### Start the peer nodes by running the following command in new terminal
```bash
    python peer.py <seed_ip> <seed_port>
```
- Replace `<seed_ip>` and `<seed_port>` with the ip address and the port of the seed node respectively.
- Run the above command in different terminals to start multiple peer nodes.