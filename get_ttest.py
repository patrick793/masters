import os
from get_result import main as get_result
from scipy import stats
import numpy as np

res_folders_list = ['results_aws_ec2', 'results_gcp_ce']
lb_methods_list = ['rr', 'rb', 'ih', 'lc', 'lb', 'lp']
conn_cnt_list = ['2', '6', '10', '20', '40']

tcporudp = int(input("[1] tcp, [2] udp: "))
distorcent = int(input("[1] central, [2] distrib: "))
lb_method = lb_methods_list[int(input("[1] rr, [2] rb, [3] ih, [4] lc, [5] lb, [6] lp: ")) - 1]
conn_cnt = input("Input Connection Count: ")

tcporudp = "tcp" if tcporudp == 1 else "udp"
distorcent = "central" if distorcent == 1 else "distrib"


data = []
data.append(get_result(res_folders_list[0] + "\\" + distorcent + "\\" + tcporudp + "\\" + lb_method + "\\" + conn_cnt, False))
os.chdir("../../../../../")
data.append(get_result(res_folders_list[1] + "\\" + distorcent + "\\" + tcporudp + "\\" + lb_method + "\\" + conn_cnt, False))

# npa = np.asarray(someListOfLists, dtype=np.float32)
np1 = np.asarray(data[0]["conn_est_interval"], dtype=np.float)
np2 = np.asarray(data[1]["conn_est_interval"], dtype=np.float)
a = stats.ttest_rel(np1, np2)
print (a)

