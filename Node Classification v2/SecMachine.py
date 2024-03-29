import subprocess

import numpy as np
import torch
import shutil
from writer import conv_reader

def update_adjacency_matrix(A, counter):
    n = len(A)
    column = np.zeros(n)
    column[counter] = 1
    A = np.hstack((A, np.atleast_2d(column).T))
    row = np.zeros(n+1)
    row[counter] = 1
    A= np.vstack ((A, row) )
    return A

def update_features(x, x_to_add, id1):
    new_name = "ciphertext{}{}.txt".format(id1, len(x)) #Name should be changed
    maximum_key = max(x.keys())
    x[maximum_key+1] = new_name
    #Update file Directory
    src = "demoData/{}".format(x_to_add)
    dest = "demoData/{}".format(new_name)
    shutil.copy(src, dest)
    return x

class SecMachine:
    def __init__(self,A):
        self.global_map = A
        self.temp = None
        self.maps = {}
        self.features = {}
        self.node_keys = {}

    def add_secure_client(self,Client):
        self.maps[Client.id] = Client.A
        self.features[Client.id]= Client.sx
        #print(Client.x)
        self.node_keys[Client.id] = list(Client.sx.keys())
        # print(list(Client.x.keys()))

    def find_connections(self, id1, id2):
        nodes1 = self.node_keys[id1]
        nodes2 = self.node_keys[id2]
        counter = 0
        for node in nodes1:
            neighborhood = np.nonzero(self.global_map[node][0])[1]
            # print(neighborhood)
            for j in neighborhood:
                if j in nodes2:
                    self.maps[id1] = update_adjacency_matrix(self.maps[id1], counter)
                    self.features[id1] = update_features(self.features[id1], self.features[id2][j], id1)
            counter = counter +1

    def compute_safe_convolution(self, id, weight, label):
        num_of_lines = len(self.features[id])
        if label == 1:
            # matrix mult
            subprocess.run(["./matrixMult", str(num_of_lines), str(weight.shape[0]), str(weight.shape[1]), str(id)])
            support = conv_reader("demoData/conv_output.txt", num_of_lines, weight.shape[1], id)
            # support = torch.mm(torch.tensor(list(self.features[id].values())), weight)
            output = torch.mm(torch.tensor(self.maps[id].A.astype(np.float32)), support.type(torch.float32))
            # true_nodes = len(self.node_keys[id])
            # output = output[0:true_nodes]
            self.temp = output
        elif label == 2:
            support = torch.mm(self.temp, weight)   
            output = torch.mm(torch.tensor(self.maps[id].A.astype(np.float32)), support)
            true_nodes = len(self.node_keys[id])
            output = output[0:true_nodes]
        
        return output

