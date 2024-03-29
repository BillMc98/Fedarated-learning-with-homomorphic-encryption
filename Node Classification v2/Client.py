import torch
import numpy as np
import torch.nn.functional as F
from helpers import accuracy
from model import GCN

class Client:
    def __init__(self, id, A, x, y):
        self.id = id
        self.A = A
        self.x = x
        self.y = y
        self.sx = {}
        self.model = None
        self.optimizer = None
        self.train_mask = None
        self.test_mask = None

    def initialize(self, hidden_channels, learning_rate, num_of_features, num_of_classes):
        self.model = GCN(nfeat=num_of_features, nhid=hidden_channels, nclass=num_of_classes, dropout=0.5)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate, weight_decay=5e-4)

    def train_local_model(self, epochs, machine):
        labels = torch.tensor(list(self.y.values()))
        print(f'Client ID: {self.id:02d} Starting Local Training')
        for epoch in range(epochs):
            self.model.train()
            self.optimizer.zero_grad()
            #output = self.model(torch.tensor(list(self.x.values())), torch.tensor(self.A.astype(np.float32)))
            output = self.model(machine, self.id)
            loss_train = F.nll_loss(output[self.train_mask], labels[self.train_mask])
            acc_train = accuracy(output[self.train_mask], labels[self.train_mask])
            loss_train.backward()
            self.optimizer.step()
            #print('Epoch: {:04d}'.format(epoch+1),'loss_train: {:.4f}'.format(loss_train.item()),'acc_train: {:.4f}'.format(acc_train.item()))
        return acc_train.item()

