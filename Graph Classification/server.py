import subprocess

from helpers import tester
import random
from writer import reader
from random import sample
random.seed(12345)

def perform_federated_round(server_model,Client_list,round_id,test_loader, args, shapes):
    Client_list = sample(Client_list, args.parameterC)
    subprocess.run(["./aggregate", str(args.parameterC)])
    global_weights = reader("demoData/Average.txt", shapes, list(server_model.state_dict().keys()))
    # for param_tensor in Client_list[0].model.state_dict():
    #     avg = (sum(c.model.state_dict()[param_tensor] for c in Client_list))/len(Client_list)
    #     server_model.state_dict()[param_tensor].copy_(avg)
    #     for cl in Client_list:
    #         cl.model.state_dict()[param_tensor].copy_(avg)
    server_model.load_state_dict(global_weights)
    for cl in Client_list:
        cl.model.load_state_dict(global_weights)

    test_acc_server = tester(server_model,test_loader)
    print(f'##Round ID={round_id}')
    print(f'Test Acc: {test_acc_server:.4f}')

    return test_acc_server

# def perform_federated_round(server_model, Client_list, round_id, test_loader, args, shapes):
#     client_list = random.sample(Client_list, args.parameterC)
#     for cl in client_list:
#         print(f"client {cl.id}:")
#         for param_tensor in server_model.state_dict():
#             print(param_tensor, "\t", cl.model.state_dict()[param_tensor])
#
#     for param_tensor in client_list[0].model.state_dict():
#         avg = (sum(c.model.state_dict()[param_tensor] for c in client_list)) / len(client_list)
#         server_model.state_dict()[param_tensor].copy_(avg)
#         for cl in client_list:
#             cl.model.state_dict()[param_tensor].copy_(avg)
#
#     print("Model's state_dict:")
#     for param_tensor in server_model.state_dict():
#         print(param_tensor, "\t", server_model.state_dict()[param_tensor])
#
#     test_acc_server = tester(server_model, test_loader)
#     print(f'##Round ID={round_id}')
#     print(f'Test Acc: {test_acc_server:.4f}')
#
#     return test_acc_server