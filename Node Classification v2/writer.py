import re

import torch
import numpy as np
import os
from collections import OrderedDict


def writer(w, numOfClients):
    MyDict = {}
    counter = 0
    if os.path.exists("demoData/client{}.txt".format(numOfClients)):
        os.remove("demoData/client{}.txt".format(numOfClients))
    for i in w:
        with open('demoData/client{}.txt'.format(numOfClients), "a") as f:
            f.write('\n')
            np.savetxt(f, w.get(i), fmt='%1.10f', newline=" ")
        MyDict[i] = "ciphertext{}{}.txt".format(numOfClients, counter)
        counter = counter + 1
    return MyDict


def WeightWriter(w):
    if os.path.exists("demoData/weights.txt"):
        os.remove("demoData/weights.txt")
    with open('demoData/weights.txt', "a") as f:
        f.write('\n')
        np.savetxt(f, w.detach().numpy(), fmt='%1.10f', newline=" ")


def ModelWriter(model, numOfClients):
    if os.path.exists("demoData/weight{}.txt".format(numOfClients)):
        os.remove("demoData/weight{}.txt".format(numOfClients))
    for i in model:
        with open('demoData/weight{}.txt'.format(numOfClients), "a") as f:
            # a = list(w.get(i).shape)
            # if len(a) > 1:
            #     f.write('{}'.format(a[1]*a[0]))
            # else:
            #     f.write('{}'.format(a[0]))
            f.write("\n")
            np.savetxt(f, model.get(i).numpy(), fmt='%1.10f')


def reader(path, shapes, keyNames):
    numOfWeights = len(keyNames)
    with open(path, "r") as f:
        # [:-3] deletes last delimiter to avoid float casting to ''
        inp = f.read().replace('(', '').replace('... ); Estimated precision: 34 bits\n', '')[:-3]
        inp = [float(x) for x in inp.split(',')]
        ans = OrderedDict()
        for i in range(numOfWeights):
            if len(shapes[i]) > 1:
                temp = torch.FloatTensor(inp[:shapes[i][0] * shapes[i][1]])
                del inp[:shapes[i][0] * shapes[i][1]]
            else:
                temp = torch.FloatTensor(inp[:shapes[i][0]])
                del inp[:shapes[i][0]]
            ans[keyNames[i]] = torch.reshape(temp, shapes[i])
    return ans


def conv_reader(path, shape1, shape2):
    matrix = np.empty([1, shape1 * shape2])
    with open(path, "r") as f:
        for i in range(shape1 * shape2):
            matrix[0, i] = float(re.findall("\d+\.\d+", f.readline())[0])
    matrix = np.reshape(matrix, (shape1, shape2))
    ans = torch.from_numpy(matrix)
    return ans
