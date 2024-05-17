import random
import numpy as np
from settings import config
import hashlib
import os
from attacker.adz import parse_api_string
import logging
from utils import blue, green, calculate_base_metrics
from tqdm import tqdm

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
        self.threshold = []
        self.selected_nodes = []  # 记录已选择的节点
        self.load_candidate_calls()

    def load_candidate_calls(self):
        for i in range(10):
            logging.info(blue("Begin loading candidate calls in cluster"+str(i)))
            with open(f"{config['action_set']}cluster{i}.txt", "r") as f:
                lst = []
                weight = []
                total_calls = sum(1 for _ in f)  # 计算候选调用总数
                f.seek(0)  # 重置文件指针
                # 添加进度条
                for line in tqdm(f.readlines()):
                    # 分割行并创建权重初始化为倒数的ActionNode
                    caller = line.split("--->")[0]
                    callee = line.split("--->")[1].split("->in:")[0]
                    apk_path = line.split("->in:")[-1]
                    # weight.append(1 / total_calls)
                    action_node = ActionNode(caller.strip(), callee.strip(),i,apk_path,1)
                    # weight.append(1 / total_calls)
                    lst.append(action_node)
                self.candidate_calls.append(lst)
                # self.candidate_calls_weight.append(weight)
                self.threshold.append(1)
                # union_set = set(lst).union(set(self.all))
                # self.all = list(union_set)
        # for node in self.all:
        #     weight_sum = 0
        #     count = 0
        #     for i in range(len(self.candidate_calls)):
        #         calls = self.candidate_calls[i]
        #         weights = self.candidate_calls_weight[i]
        #         if node in calls:
        #             weight_sum += weights[calls.index(node)]
        #             count+=1
        #     self.all_weight.append(weight_sum / count)
        logging.info(blue("Load candidate calls successfully."))
        

    def select_random_action(self, cluster_index,ori_apis,ori_callers,ori_calls):
        # 从指定簇的候选调用中随机选择一个ActionNode，考虑到节点的权重
        # candidates = [node for node in self.candidate_calls[cluster_index] if node not in self.selected_nodes and f"{node.caller}--->{node.callee}" not in ori_calls and (node.caller in ori_callers or node.callee in ori_apis)]
        apis = [node for node in self.candidate_calls[cluster_index] if f"{node.caller}--->{node.callee}" not in ori_calls and (node.caller in ori_callers or node.callee in ori_apis) ]
        cluster_candidates = [node for node in apis if node not in self.selected_nodes]  
        # weights = []
        # for node in cluster_candidates:
        #     index = self.candidate_calls[cluster_index].index(node)
        #     weights.append(self.candidate_calls_weight[cluster_index][index])
        # weights = [self.candidate_calls_weight[cluster_index][index] for index, node in enumerate(self.candidate_calls[cluster_index]) if node in cluster_candidates]
        weights = [x.weight for x in cluster_candidates]
        if len(cluster_candidates) == 0:
            return None
        # more = [node for index, node in enumerate(cluster_candidates) if weights[index]>(1/len(self.candidate_calls_weight[cluster_index]))]
        # unselect = [node for index, node in enumerate(cluster_candidates) if weights[index]==(1/len(self.candidate_calls_weight[cluster_index]))]
        more = [node for node in cluster_candidates if node.weight > sum(weights)/len(weights)]
        unselect = [node for node in cluster_candidates if node.weight == 1]
        pro = random.uniform(0, 1)
        if pro< self.threshold[cluster_index] or len(more)==0:
            node = random.choice(unselect)
        else:
            if pro<0.5:
                # 获取weight列表最大值的索引
                max_index = weights.index(max(weights))
                # 根据索引获取candidate
                max_candidate = cluster_candidates[max_index]
                node = max_candidate
            else:
                index = random.randint(0, len(more)-1)
                node = more[index]
        # total_weight = sum(weights[candidates.index(node)] for node in candidates)
        # rand = random.uniform(0, total_weight)
        # cumulative_weight = 0
        # for node in cluster_candidates:
        #     cumulative_weight += weights[cluster_candidates.index(node)]
        #     if rand < cumulative_weight and "[)" not in node.caller and "[)" not in node.callee:
        #         self.selected_nodes.append(node)
        #         return node
        # node = random.choice(candidates)
        self.selected_nodes.append(node)
        return node
    
    def reset_selected(self):
        self.selected_nodes = []
    
    def update_candidate_call_pro(self,cluster,call,result):
        calls = self.candidate_calls[cluster]      
        index = calls.index(call)
        # self.candidate_calls_weight[cluster][index] *= (1+result) 
        self.candidate_calls[cluster][index].weight *= (1-result*2) 
        if result > 0:
            self.threshold[cluster] *= 0.99

