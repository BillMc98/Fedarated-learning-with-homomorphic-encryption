import torch
import numpy as np
import os
from collections import OrderedDict


def writer(w, numOfClients):
    if os.path.exists("demoData/client{}.txt".format(numOfClients)):
        os.remove("demoData/client{}.txt".format(numOfClients))
    for i in w:
        with open('demoData/client{}.txt'.format(numOfClients), "a") as f:
            # a = list(w.get(i).shape)
            # if len(a) > 1:
            #     f.write('{}'.format(a[1]*a[0]))
            # else:
            #     f.write('{}'.format(a[0]))
            f.write("\n")
            np.savetxt(f, w.get(i).numpy(), fmt='%1.10f')

def reader(path, shapes, keyNames):
    numOfWeights = len(keyNames)
    with open(path, "r") as f:
        # [:-3] deletes last delimiter to avoid float casting to ''
        inp = f.read().replace('(', '').replace('... ); Estimated precision: 34 bits\n', '')[:-3]
        inp = [float(x) for x in inp.split(',')]
        ans = OrderedDict()
        for i in range(numOfWeights):
            if len(shapes[i]) > 1:
                temp = torch.FloatTensor(inp[:shapes[i][0]*shapes[i][1]])
                del inp[:shapes[i][0]*shapes[i][1]]
            else:
                temp = torch.FloatTensor(inp[:shapes[i][0]])
                del inp[:shapes[i][0]]
            ans[keyNames[i]] = torch.reshape(temp, shapes[i])
    return ans
