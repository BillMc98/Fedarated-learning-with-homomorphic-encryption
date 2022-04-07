# A federated learning Example-Setting for Node Classification using FHE to avoid data leakage between Clients
import torch, copy,random
import networkx as nx
import subprocess
import numpy as np
import matplotlib.pyplot as plt
from helpers import tester
from writer import writer, reader
from data_preprocess import load_data, split_communities, create_clients

torch.manual_seed(12345)
random.seed(12345)
torch.cuda.manual_seed_all(12345)
torch.backends.cudnn.deterministic = True
np.random.seed(12345)

global_graph, num_of_features, num_of_classes,num_of_nodes, prim = load_data()
G1, G2, G3 = split_communities(global_graph)

Client1, Client2, Client3 = create_clients(G1,G2,G3)

# Create Global and Local Models
from model import GCN
model = GCN(nfeat=num_of_features, nhid=16, nclass=num_of_classes, dropout=0.5)

# Assign Model, Optimizer to Clients
Client1.set_model(copy.deepcopy(model))
Client2.set_model(copy.deepcopy(model))
Client3.set_model(copy.deepcopy(model))

# Create Train/Test masks
from helpers import simple_train_test_split
Client1 = simple_train_test_split(Client1, 0.7)
Client2 = simple_train_test_split(Client2, 0.7)
Client3 = simple_train_test_split(Client3, 0.7)


# Create and initialize Aggregation Server
from Server import Aggregation_Server
MyServer = Aggregation_Server()
MyServer.set_model(copy.deepcopy(model))

subprocess.run("./initialize")
writer(Client1.x, 1)
subprocess.run(["./encrypt", "1"])
writer(Client1.x, 2)
subprocess.run(["./encrypt", "2"])
writer(Client3.x, 3)
subprocess.run(["./encrypt", "3"])

# Create and initialize Security Machine
from SecMachine import SecMachine
MyMachine = SecMachine(nx.to_numpy_matrix(prim))
MyMachine.add_secure_client(Client1)
MyMachine.add_secure_client(Client2)
MyMachine.add_secure_client(Client3)
MyMachine.find_connections(1, 2)
MyMachine.find_connections(1, 3)
MyMachine.find_connections(2, 1)
MyMachine.find_connections(2, 3)
MyMachine.find_connections(3, 1)
MyMachine.find_connections(3, 2)

res=0
localdraw1 = []
localdraw2 = []
localdraw3 = []
serverdraw = []
# Federated Learning
for round in range(10):
    #Train Local Models
    Client1.train_local_model(epochs=10, machine=MyMachine)
    Client2.train_local_model(epochs=10, machine=MyMachine)
    Client3.train_local_model(epochs=10, machine=MyMachine)

    # if round == 0:
    #     res = (tester(Client2.model, Client1, MyMachine) +tester(Client2.model, Client2, MyMachine) + tester(Client2.model, Client3, MyMachine))/3
    #     localdraw1.append(res)
    # else:
    #     localdraw1.append(res)

    localdraw1.append(tester(Client1.model, Client1, MyMachine))
    localdraw2.append(tester(Client2.model, Client2, MyMachine))
    localdraw3.append(tester(Client3.model, Client3, MyMachine))

    # FedAvg Local Models on Server
    Client1.model, Client2.model, Client3.model = MyServer.perform_fed_avg(Client1.model, Client2.model, Client3.model)

    # Test Server Model on every clients data
    server_acc = (tester(MyServer.model, Client1, MyMachine) +tester(MyServer.model, Client2, MyMachine) + tester(MyServer.model, Client3, MyMachine))/3
    print("Server Accuracy")
    print(server_acc.item())
    serverdraw.append(server_acc.item())

# print(res)
plt.figure(figsize=(10,5))
plt.title("Testing Accuracy per Federated Round")
# plt.title("Federated vs Centralized Learning")
plt.plot(localdraw1, label="Client1")
plt.plot(localdraw2, label="Client2")
plt.plot(localdraw3, label="Client3")
plt.plot(serverdraw, label="Server")
plt.xlabel("Federated Round")
plt.ylabel("Accuracy")
plt.legend()
plt.show()