import psutil

print("NIC info:")
print(psutil.net_if_stats())