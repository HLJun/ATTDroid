import random
import numpy as np
from settings import config
import hashlib
import os
from attacker.adz import parse_api_string
import logging
from utils import blue, green, calculate_base_metrics
from tqdm import tqdm
import json

class ActionNode:
    def __init__(self,caller,callee,cluster,apk_path,weight):
        self.caller = caller
        self.callee = callee
        self.cluster = cluster
        self.apk_path = apk_path
        self.weight = weight
        self.smali_path = None
        self.smali = None
        self.par_smali_path()

    def par_smali_path(self):
        self.smali_path = f"/data/hlj/datas/cic20/code/cluster{self.cluster}/{self.caller}.txt"
        if os.path.exists(self.smali_path):
            self.get_smali()

    def get_smali(self):
        with open(self.smali_path,'r') as file:
            self.smali = file.readlines()

class RandomPerturbationSelector:
    def __init__(self):
        self.candidate_calls = []
        self.candidate_calls_weight = []
        self.threshold = [] # 记录每个簇的threshold
        self.effi_calls = {} # 记录每个簇的有效APIcall
        self.selected_nodes = []  # 记录已选择的节点
        self.load_candidate_calls()

    def load_candidate_calls(self):
        with open("/home/hlj/code/android/code/ATTDroid/model_results/cic20/jsons/effi_calls.json",'r') as file:
            self.effi_calls = json.load(file)
        for i in range(10):
            logging.info(blue("Begin loading candidate calls in cluster"+str(i)))
            with open(f"{config['action_set']}cluster{i}.txt", "r") as f:
                lst = []
                f.seek(0)  # 重置文件指针
                # 添加进度条
                for line in tqdm(f.readlines()):
                    # 分割行并创建权重初始化为倒数的ActionNode
                    caller = line.split("--->")[0]
                    callee = line.split("--->")[1].split("->in:")[0]
                    apk_path = line.split("->in:")[-1]
                    action_node = ActionNode(caller.strip(), callee.strip(),i,apk_path,1)
                    lst.append(action_node)
                self.candidate_calls.append(lst)
                self.threshold.append(0.5)
        
        logging.info(blue("Load candidate calls successfully."))
        

    def select_random_action(self, cluster_index,ori_apis,ori_callers,ori_calls):
        out = ""
        # 从指定簇的候选调用中随机选择一个ActionNode，考虑到节点的权重
        apis = [node for node in self.candidate_calls[cluster_index] if f"{node.caller}--->{node.callee}" not in ori_calls and (node.caller in ori_callers or node.callee in ori_apis) ]
        cluster_candidates = [node for node in apis if node not in self.selected_nodes]  
        effi_node = [node for node in cluster_candidates if f"{node.caller}->{node.callee}" in self.effi_calls[str(cluster_index)]]
        for node in effi_node:
            if node.weight == 1:
                node.weight = 1.5
        if len(cluster_candidates) == 0:
            return None
        unselect = [node for node in cluster_candidates if node.weight == 1]
        ri = random.randint(0,100)
        if ri %2 == 0:
            pro = random.uniform(0, 0.5)
        else:
            pro = random.uniform(0.5, 1)
        if pro < self.threshold[cluster_index] or len(effi_node)==0:
            node = random.choice(unselect)
            out+=f"select unselect node with thershold: {self.threshold[cluster_index]} and pro: {pro}\n"
        else:
            if pro < 0.5:
                # 直接使用最有效的
                out+=f"select most effi_node with thershold: {self.threshold[cluster_index]} and pro: {pro}\n"
                effi_weights = [x.weight for x in effi_node]
                max_index = effi_weights.index(max(effi_weights))
                # 根据索引获取candidate
                node = effi_node[max_index]
            else:
                # 从有效的里面随机选一个
                out+=f"select from effi_node with thershold: {self.threshold[cluster_index]} and pro: {pro}\n"
                index = random.randint(0, len(effi_node)-1)
                node = effi_node[index]
        self.selected_nodes.append(node)
        return node,out
    
    def reset_selected(self):
        self.selected_nodes = []
    
    def update_candidate_call_pro(self,cluster,call,result):
        calls = self.candidate_calls[cluster]      
        index = calls.index(call)
        self.candidate_calls[cluster][index].weight *= (1-result) 
        if 0 - result > 1e-1:
            self.threshold[cluster] *= 0.9
            if call not in self.effi_calls[str(cluster)]:
                self.effi_calls[str(cluster)].append(f"{call.caller}->{call.callee}")
                with open("/home/hlj/code/android/code/ATTDroid/model_results/cic20/jsons/effi_calls.json",'w') as file:
                    json.dump(self.effi_calls,file,indent=4)

