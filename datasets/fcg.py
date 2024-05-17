import os
import re
import queue
import networkx as nx
import matplotlib.pyplot as plt
from settings import config
import numpy as np
import networkx as nx
import os
from karateclub import Graph2Vec
import numpy as np
from sklearn.cluster import KMeans
from collections import Counter
import json
import shutil
import hashlib

type_map = {
        "V": "void", 
        "Z": "boolean",
        "B": "byte",
        "S": "short", 
        "C": "char",
        "I": "int",
        "J": "long",
        "F": "float",
        "D": "double",
        "Ljava/lang/String;": "String"
}

prefix_list = ['java',
    'org.apache',
    'androidx',
    'com.ti',
    'com.android',
    'com.google',
    'com.squareup',
    'android',
    'com.software',
    'com.facebook',
    'com.airbit',
    'com.github.droidfu',
    ]

sensitive_apis = []
with open("datasets/dangerous/sensitive_api_all.txt", 'r') as file:
    for line in file:
        line = line.strip()
        sensitive_apis.append(line)

# 自定义函数调用
class APICall:
    def __init__(self, 
                 caller_class, 
                 caller_method,
                 caller_return_type,
                 caller_params,
                 callee_class,
                 callee_method,
                 callee_return_type,
                 callee_params):
        
        self.caller_class = caller_class
        self.caller_method = caller_method
        self.caller_return_type = caller_return_type
        self.caller_params = caller_params
        self.callee_class = callee_class 
        self.callee_method = callee_method
        self.callee_return_type = callee_return_type
        self.callee_params = callee_params
    def __str__(self):
        return f"<{self.caller_class}: {self.caller_return_type} {self.caller_method}({self.caller_params})>--->{self.callee_class}: {self.callee_return_type} {self.callee_method}({self.callee_params})>"


# 将函数调用解析为指定格式
def parseInvoke(line,call):
    call.callee_return_type=line.split(')')[-1].replace("\n",'')
    if call.callee_return_type in type_map:
        call.callee_return_type = type_map.get(call.callee_return_type)
    call.callee_class=line.split(';')[0].split()[-1].strip()
    call.callee_method=line.split('->')[1].split('(')[0]
    m = re.search("\(([^\)]+)\)", line)
    if m:
        call.callee_params = m.group(1)
    else:
        call.callee_params = ""
    return call

# 解析method为指定格式
def parse_method(lines):
    methods = set()
    caller_class = ""
    caller_method = ""
    caller_params = ""
    caller_return_type = ""
    for line in lines:
        if line.startswith(".class"):
            caller_class = line.split()[-1].replace(';',"")
        if line.startswith(".method"):
            caller_method = line.split()[-1].split('(')[0]
            m = re.search("\(([^\)]+)\)", line)
            if m:
                caller_params = m.group(1)
            else:
                caller_params = ""
            caller_return_type = line.split(')')[-1].replace("\n",'')
            if caller_return_type in type_map:
                caller_return_type = type_map.get(caller_return_type)
        if line.startswith("    invoke"):
            call = APICall(
                caller_class = caller_class,
                caller_method = caller_method,  
                caller_params = caller_params,
                caller_return_type = caller_return_type,
                callee_class = None,
                callee_method = None,  
                callee_params = None,
                callee_return_type = None
            )
            call = parseInvoke(line,call)
            methods.add(call)
        if ".end method" in  line:
            caller_method = ""
            caller_params = ""
            caller_return_type = ""
    return list(methods)
        

# 提取所有methods
def extract_method_calls(file):
    with open(file) as f:
        lines = f.readlines()
        call_list = parse_method(lines)
    return call_list

# 解析参数列表
def parse_params(params):
    # params = params.split('(')[-1].split(')')[0]
    params_str = ''
    if params!='':
        params = params.split(';')
        for x in params:
            if x.startswith('['):
                params_str+=('[')
                x = x[1:]
            while x != '' and x[0] in type_map:
                params_str+=(type_map.get(x[0])+",")
                x = x[1:]
            if x.startswith('['):
                params_str+=('[')
                x = x[1:]
            if x.startswith('L'):
                params_str+=(x[1:]+',')
            if x in type_map:
                x = type_map.get(x)
                params_str+=(x+',')
    params_str = params_str.strip(',')
    params_str = params_str.replace('/','.')
    return params_str

# 解析返回值类型
def parse_return(returns): 
    return_type = returns.split(')')[-1].split('->')[0].strip('\n')
    returns = ''
    if return_type.startswith('['):
        returns+=('[')
        return_type = return_type[1:]
    if return_type.startswith('L'):
        return_type = return_type[1:]
        returns+=return_type
    if return_type in type_map:
        returns+= type_map.get(return_type)
    returns = returns.strip(';')
    if returns == "":
        returns = return_type
    returns = returns.replace('/','.')
    return returns

# 转换为指定格式
def trans(api_call):
    caller_package = api_call.split(':')[0].replace('<L','').replace('/','.')
    caller_return = parse_return(api_call.split(' ')[1])
    caller_method = api_call.split(' ')[2].split('(')[0]
    caller_params = api_call.split('(')[1].split(')')[0]
    if caller_params != "":
        caller_params = parse_params(caller_params)

    callee_package = api_call.split('--->')[1].split(':')[0].strip('L').replace('/','.')
    callee_return = parse_return(api_call.split(' ')[-2])
    callee_method = api_call.split(' ')[-1].split('(')[0]
    callee_params = api_call.split('(')[-1].split(')')[0]
    if callee_params != "":
        callee_params = parse_params(callee_params)

    callee_api = callee_package+"."+callee_method+"("+callee_params+")"+callee_return
    caller_api = caller_package+"."+caller_method+"("+caller_params+")"+caller_return
    return caller_api,callee_api

# 解析smali文件，提取函数调用关系
def parseSmali( smali_path ,out_path):
    # dir_path = "/home/hlj/code/android/code/out"
    # out_path = "/home/hlj/code/android/code//apks/cic17/ben/"
    call_list = []
    processed = set()
    for root, dirs, files in os.walk(smali_path):
        for index, f in enumerate(files, start=1):
            file_path = os.path.join(root, f)
            # 如果文件是apk类型，则获取应用名、包名、签名等信息
            if f.endswith(".smali"):
                call_list.extend(extract_method_calls(file_path))
    out = ""
    for call in call_list:
        caller_api,callee_api = trans(str(call))
        line =  caller_api + "--->" + callee_api
        if line not in processed:
            out+=line + '\n'
            processed.add(line)
        
    if out!="":
        with open(out_path, 'w') as outfile:
            outfile.write(out)
        return True
    else:
        return False


def findApk(dir_path,out_path):
    if not os.path.isdir(dir_path):
        print('参数输入有误，不是一个目录...')
        return
    for root, dirs, files in os.walk(dir_path):
        for index, f in enumerate(files, start=1):
            file_path = os.path.join(root, f)
            # 如果文件是apk类型，则获取应用名、包名、签名等信息
            if f.endswith(".apk"):
                if not os.path.exists(out_path+f.replace('.apk','.txt')):
                    parse_dir = out_path+f.split('.')[0]+"/"
                    cmd = "apktool d "+file_path+" -o "+parse_dir+ " -f"
                    os.system(cmd)
                    parseSmali(f,parse_dir,out_path)
                    cmd = "rm -rf "+parse_dir
                    os.system(cmd)

# 定义一个函数，用于遍历指定目录下的文件并处理
def extract_fcg(apk_path,out_path):
    parse_dir = "/home/hlj/dev/shm/gnip/tmp/unpack/"+apk_path.split("/")[-1].replace(".apk","/")
    if apk_path.endswith(".apk") and not os.path.exists(parse_dir) and not os.path.exists(out_path):
        cmd = "apktool d "+apk_path+" -o "+parse_dir + ' -f'
        os.system(cmd)
        flag = parseSmali(parse_dir,out_path)
        cmd = "rm -rf "+parse_dir
        os.system(cmd)
        return flag


class APIGraph:
    def __json__(self):
        filtered_predecessors = {}
        filtered_successors = {}
        for api in self.predecessors.keys():
            if self.is_system_api(api):  
                filtered_predecessors[api] = self.predecessors[api]

        for api in self.successors.keys():
            if self.is_system_api(api):
                filtered_successors[api] = self.successors[api]
        return {
            'predecessors': list(self.predecessors),
            'successors': list(self.successors),
            'system_apis':list(self.system_api)
        }
    def __init__(self):
        self.predecessors = {}  # 前驱API的字典
        self.successors = {}    # 后继API的字典
        self.system_api = set()
    def is_system_api(self,api):
        for prefix in prefix_list:
            if api.startswith(prefix):
                return True
        return False

    def add_call_relation(self, caller_api, callee_api):
        if self.is_system_api(callee_api):
            self.system_api.add(callee_api)
        if self.is_system_api(caller_api):
            self.system_api.add(caller_api)
        self.successors.setdefault(caller_api, set()).add(callee_api)
        self.predecessors.setdefault(callee_api, set()).add(caller_api)


# 解析函数调用关系并添加到API图中
def parse_call_relations(file_path,api_graph):
    processed = set()
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line not in processed:
                processed.add(line)
                caller_api = line.split("--->")[0]
                callee_api = line.split("--->")[1]
                api_graph.add_call_relation(caller_api, callee_api)

class APICallGraph:
    def __init__(self):
        self.graph = nx.DiGraph()  # 创建一个有向图
        self.nodes = set()
        self.edges = 0

    def add_call_relation(self, caller, callee):
        # 添加函数调用关系到图中
        self.graph.add_edge(caller, callee)
        self.nodes.add(caller)
        self.nodes.add(callee)
        self.edges+=1

    def find_connected_subgraphs(self):
        # 提取图中的连通子图
        connected_subgraphs = [subgraph for subgraph in nx.connected_components(self.graph.to_undirected())]
        return connected_subgraphs

    def visualize_graph(self):
        # 绘制图形
        pos = nx.spring_layout(self.graph)  # 定义节点的布局
        nx.draw(self.graph, pos, with_labels=True)
        plt.show()
        
    def save_graph(self, file_path):
        # 将图保存到文件中
        nx.write_graphml(self.graph, file_path)


def sfcg_grams(n,fcg_path,sfcg_txt_path):
    # 提取敏感API函数调用子图 n-grams
    gram_num = n
    # 创建API图对象
    api_graph = APIGraph()
    out = ""
    parse_call_relations(fcg_path,api_graph)
    predecessors,successors = api_graph.predecessors,api_graph.successors
    processed = set()
    processed_line = set()
    wait_process = queue.Queue()
    for api in api_graph.system_api:
        if api in sensitive_apis:
            wait_process.put(api)
    while not wait_process.empty() and gram_num>0:
        gram_num -= 1
        num = wait_process.qsize()
        for i in range(num):
            api = wait_process.get()
            if api in predecessors.keys():
                prev = predecessors[api]
                for item in prev:
                    if item not in processed and (gram_num>1 or item in api_graph.system_api):
                        processed.add(item)
                        wait_process.put(item)
                    line = item+"--->"+api
                    if line not in processed_line:
                        processed_line.add(line)
                        out+=line+"\n"
                        
            if api in successors.keys():
                next = successors[api]
                for item in next:
                    if item not in processed and (gram_num>1 or item in api_graph.system_api):
                        processed.add(item)
                        wait_process.put(item)
                    line = api+"--->"+item
                    if line not in processed_line:
                        processed_line.add(line)
                        out+=line+"\n"
    if out != "":
        with open(sfcg_txt_path,'w') as out_file:
            out_file.write(out)
            return True
    else:
        return False

# 提取敏感API函数调用子图 n-nodes
def sfcg_nodes(node_num,fcg_path,sfcg_txt_path):
    # 创建API图对象
    api_graph = APIGraph()
    out = ""
    parse_call_relations(fcg_path,api_graph)
    predecessors,successors = api_graph.predecessors,api_graph.successors
    processed = set()
    nodes = set()
    processed_line = set()
    wait_process = queue.Queue()
    wp = set()
    for api in api_graph.system_api:
        if api in sensitive_apis:
            wait_process.put(api)
            wp.add(api)
    flag = False
    while not wait_process.empty() and len(nodes)<node_num:
        num = wait_process.qsize()
        for i in range(num):
            api = wait_process.get()
            nodes.add(api)
            processed.add(api)
            if api in predecessors.keys():
                prev = predecessors[api]
                for item in prev:
                    if item not in processed and item not in wp:
                        wait_process.put(item)
                        wp.add(item)
                    if item not in nodes:
                        nodes.add(item)
                    line = item+"--->"+api
                    if line not in processed_line:
                        processed_line.add(line)
                        out+=line+"\n"
                    if len(nodes)>=node_num:
                        flag = True
                        break
                if flag:
                    break
                        
            if api in successors.keys():
                next = successors[api]
                for item in next:
                    if item not in nodes:
                        nodes.add(item)
                    if item not in processed and item not in wp:
                        wait_process.put(item)
                        wp.add(item)
                    line = api+"--->"+item
                    if line not in processed_line:
                        processed_line.add(line)
                        out+=line+"\n"
                    if len(nodes)>=node_num:
                        flag = True
                        break
                if flag:
                    break
    if out != "":
        with open(sfcg_txt_path,'w') as out_file:
            out_file.write(out)


def txt2graph(sfcg_txt_path):
    if not os.path.exists(sfcg_txt_path):
        return
    sfcg_gml_path = sfcg_txt_path.replace("/txt/","/gml/").replace(".txt",".graphmal")
    dir = sfcg_gml_path.replace(os.path.basename(sfcg_gml_path),'')
    if not os.path.exists(dir):
        os.makedirs(dir,exist_ok=True)
    # 添加敏感系统 API 调用关系到图中
    with open(sfcg_txt_path,'r') as file:
        api_call_graph = APICallGraph()
        for line in file:
            caller = line.strip().split("--->")[0].split('(')[0].split('.')[-1]
            callee = line.strip().split("--->")[1].split('(')[0].split('.')[-1]
            api_call_graph.add_call_relation(caller,callee)
        connected_subgraphs = api_call_graph.find_connected_subgraphs()
        if len(connected_subgraphs) >1:
            for sub in connected_subgraphs:
                api_call_graph.add_call_relation("dummyMethod",list(sub)[0])
        api_call_graph.save_graph(sfcg_gml_path)


# 提取每个fcg的sfcg
def ex_sfcg(fcg_path,type=0,ngrams=2,nnodes=100):
    if type==0:
        out_path_grams = fcg_path.replace('/fcg/',f'/sfcg/sfcg{ngrams}gram/txt/')
        dir = out_path_grams.replace(os.path.basename(out_path_grams),'')
        if not os.path.exists(dir):
            os.makedirs(dir,exist_ok=True)
        flag = sfcg_grams(ngrams,fcg_path,out_path_grams)
    else:
        out_path_nodes = fcg_path.replace('/fcg/',f'/sfcg/sfcg{nnodes}node/txt/')
        dir = out_path_grams.replace(os.path.basename(out_path_nodes),'')
        if not os.path.exists(dir):
            os.makedirs(dir,exist_ok=True)
        flag = sfcg_nodes(nnodes,fcg_path,out_path_nodes)
    return flag


# 读取graphml，并返回graph_list,graph_dict,dic2,file_path_list
def read_graphml_files(paths):
    graph_list = []
    file_path_list = []
    # 文件名和graph1的映射
    graph_dict  = dict()
    # graph1 和 graph2的映射
    dic2 = dict()
    for path in paths:
        file_path_list.append(path)
        graph = nx.read_graphml(path)
        graph_dict [path] = graph
        graph_list.append(graph)
    # 重新编号图中的节点
    for idx, graph in enumerate(graph_list):
        rgraph = reindex_nodes(graph)
        graph_list[idx] = rgraph
        dic2[graph] = rgraph
                # 将有向图转换为无向图
                # undirected_graph = graph.to_undirected()
                # graph_list.append(undirected_graph)
    return graph_list,graph_dict,dic2,file_path_list

# 对节点重新编号
def reindex_nodes(graph):
    mapping = {node: idx for idx, node in enumerate(graph.nodes())}
    reindexed_graph = nx.relabel_nodes(graph, mapping)
    return reindexed_graph

# 使用Graph2Vec对graph_list进行嵌入
def embedding(graph_list):
    # 创建 Graph2Vec 模型
    model = Graph2Vec()

    # 训练模型
    model.fit(graph_list)

    # 获取图的嵌入向量
    embeddings = model.get_embedding()

    # 假设目标文件路径为 'embeddings.npy'
    target_file = 'sen_fcg_embeddings.npy'
    # 将嵌入向量保存为 Numpy 二进制文件
    np.save(target_file, embeddings)
    return embeddings     

# 对每个图进行 KNN 聚类 10 次，并返回每个图所属的类别
def mal_cluster(paths , out_file, n_clusters=10,knn_times = 10):
    graph_list,graph_dict,dic2,fpl  = read_graphml_files(paths)
    embeddings = embedding(graph_list)
    # 使用 KMeans 聚类
    kmeans = KMeans(n_clusters=n_clusters)
    cluster_list = [[] for i in range(len(graph_list))]
    for i in range(knn_times):
        clusters = kmeans.fit_predict(embeddings)
        for index, cluster_id in enumerate(clusters):
            cluster_list[index].append(cluster_id)

    # 初始化一个列表，用于保存每个一维数组中出现次数最多的数
    final_cluster = []
    # 遍历二维数组的每个一维数组
    for row in cluster_list:
        # 使用Counter类统计当前一维数组中每个元素出现的次数
        counter = Counter(row)
        # 找到出现次数最多的元素
        most_common_value = counter.most_common(1)[0][0]
        # 将出现次数最多的元素添加到保存结果的列表中
        final_cluster.append(most_common_value)
    final_cluster = [int(value) for value in final_cluster]
    # 将聚类结果保存到json文件中
    dct = dict()
    for path, graph in graph_dict.items():
        index = graph_list.index(dic2[graph])
        cluster = final_cluster[index]
        dct[path.split('/')[-1].replace('.graphmal','')] = cluster
    with open (out_file,'w') as json_file:
        json.dump(dct, json_file, indent=4)
    return out_file

def is_sensitive_api(node):
    # 判断是否为敏感API节点
    return node in sensitive_apis

def is_system_api(node):
    # 判断是否为系统API节点
    for prefix in prefix_list:
        if node.startswith(prefix):
            return True
    return False

def read_sensitive_fcgs(file_path):
    """
    从文件中读取敏感FCG的调用关系，并返回函数调用的集合和每种节点类型的函数调用数量。

    参数：
        file_path (str): 文件路径。

    返回值：
        set: 函数调用的集合。
        dict: 每种节点类型的函数调用数量。
    """
    with open(file_path, 'r') as file:
        fcg_nodes = set()
        fcg_calls = set(file.read().splitlines())
        for calls in fcg_calls:
            for node in calls.split('--->'):
                fcg_nodes.add(node)

    sensitive_api_nodes = [node for node in fcg_nodes if is_sensitive_api(node)]
    system_api_nodes = [node for node in fcg_nodes if is_system_api(node) and node not in sensitive_api_nodes]
    connection_nodes = [node for node in fcg_nodes if node not in sensitive_api_nodes and node not in system_api_nodes]

    return {'calls':list(fcg_calls), 'apis':{
                    'sensitive_api': list(sensitive_api_nodes),
                    'system_api': list(system_api_nodes),
                    'connection': list(connection_nodes)},
                    'filename':file_path.split('/')[-1]
                    }

def save_sfcg_to_json(fcg, output_file):
    with open(output_file, 'w') as outfile:
        json.dump(fcg, outfile, indent=4)

# 提取目录下SFCG信息
def data2sfcg(sfcg_path_list,out_path):
    sfcg_list = []
    for sfcg_path in sfcg_path_list:
        sfcg = read_sensitive_fcgs(sfcg_path)
        sfcg_list.append(sfcg)
    json_data = {"sfcgs": sfcg_list}
    save_sfcg_to_json(json_data,out_path)

# 提取一个簇的SFCG信息
def cluster2sfcg(mals,cluster_info,n):
    cluster_mals = []
    for i in range(n):
        cluster_mals.append([])
    for mal in mals:
        cluster_mals[cluster_info[mal['sample_path'].split('/')[-1].replace(".apk","")]].append(mal['sfcg_txt_path'])
    # 按簇提取fcg信息
    for i in range(n):
        clu_data = cluster_mals[i]
        sfcg_list = []
        for item in clu_data:
            sfcg = read_sensitive_fcgs(item)
            sfcg_list.append(sfcg)
        json_data = {"sfcgs": sfcg_list}
        save_sfcg_to_json(json_data,config['sfcg_dirs']+"/cluster"+str(i)+"sfcg.json")


def read_sfcgs(file_path):
    with open(file_path, "r") as json_file:
        sfcgs_data = json.load(json_file)['sfcgs']
    return sfcgs_data

def calculate_node_sim_mal(sfcg1_nodes, sfcg2_nodes):
    """
    计算两个敏感SFCG的节点相似度，考虑节点类型的权重。

    参数：
        sfcg1_nodes(set): 第一个敏感SFCG的不同类型节点set。
        sfcg2_nodes(set): 第二个敏感SFCG的不同类型节点set。

    返回值：
        float: 相似度，考虑节点类型权重。
    """
    total_similarity = 0

    # 根据节点类型权重计算相似度
    for node_type in ['sensitive_api', 'system_api', 'connection']:
        weight = get_node_weight(node_type)
        total_similarity += weight* 0.1 * calculate_node_type_sim_mal(sfcg1_nodes[node_type], sfcg2_nodes[node_type])

    return total_similarity

def calculate_node_type_sim_mal(sfcg1_nodes, sfcg2_nodes):
    # 根据节点类型的数量和权重计算相似度
    common_nodes = set(sfcg1_nodes) & set(sfcg2_nodes)
    return len(common_nodes) / len(sfcg1_nodes) if len(common_nodes) > 0 else 0

def get_node_weight(node_type):
    # 返回每种节点类型的权重
    weights = {'sensitive_api': 5, 'system_api': 3, 'connection': 2}
    return weights[node_type]

def calculate_node_type_sim(sfcg1_nodes, sfcg2_nodes):
    # 根据节点类型的数量和权重计算相似度
    common_nodes = set(sfcg1_nodes) & set(sfcg2_nodes)
    total_nodes = len(sfcg1_nodes) + len(sfcg2_nodes)
    return 2*len(common_nodes) / total_nodes if total_nodes > 0 else 0

# 逻辑修改：计算两fcg相似度->恶意良性软件相似度
def cal2sim(sfcg1,sfcg2):
    # fcg1_calls = sfcg1['calls']
    # fcg2_calls = sfcg2['calls']
    fcg1_node_list = sfcg1['apis']
    fcg2_node_list = sfcg2['apis']
    # sim = 0.2* calculate_call_sim_mal(fcg1_calls,fcg2_calls) + 0.8*calculate_node_sim_mal(fcg1_node_list, fcg2_node_list)
    sim = calculate_node_sim_mal(fcg1_node_list, fcg2_node_list)
    return sim

# fcg与不同簇的fcg_list的平均相似度
def avg_sim(sfcg1,sfcg_list):
    sims = []
    for sfcg in sfcg_list:
        sim = cal2sim(sfcg, sfcg1)
        sims.append(sim)
    return sum(sims)/len(sims)

# 提取每个簇中最相似的良性软件
def find_cluster_sim_ben(ben_json_path,mal_jsons_dir,out_path,sample_rate = 0.2):
    # ben_path = "/data1/hlj/apks/cic20/ben/SFCG/sfcg2gram/txt/fcg.json"
    ben_fcg_list = read_sfcgs(ben_json_path)
    sim_ben_dct = {}
    for i in range(10):
        mal_path = f"{mal_jsons_dir}/cluster{str(i)}sfcg.json"
        mal_fcg_list = read_sfcgs(mal_path)
        sim = [avg_sim(ben,mal_fcg_list) for ben in ben_fcg_list]
        topn = len(mal_fcg_list)//(1/sample_rate)
        top_similar_samples_indices = np.argsort(sim)[-int(topn):][::-1]
        sim_ben_dct[f"cluster{str(i)}"]= [ben_fcg_list[x]['filename'] for x in top_similar_samples_indices]
        with open(out_path,'w')as file:
            json.dump(sim_ben_dct,file,indent=4)

def extract_class_name(string):
    return '/'.join(string.split('(')[0].split(".")[0:-1])

def parse_method_name(string):
    return string.split('(')[0].split(".")[-1]

def parse_code(lines,method_name):
    method = ""
    flag = False
    for line in lines:
        if line.startswith(".method"):
            if method_name in line:
                flag = True
        if flag:
            method += line
        if ".end method" in  line and flag:
            return method
    return ""


def get_code(apk_path,caller,cluster):
    # 保存method片段的根目录，簇
    out_path = "/data1/hlj/datas/cic20/code/cluster"+str(cluster)+'/'
    if not os.path.exists(out_path):
        os.makedirs(out_path)
    # 反编译目录
    tmp_dir = "/home/hlj/dev/shm/gnip/tmp/unpack/"
    cmd = f"apktool d {apk_path.strip()} -o {tmp_dir} -f"
    os.system(cmd)
    out = ""
    # 构建文件名
    method_hash = hashlib.sha256(caller.encode()).hexdigest()
    caller_name = caller.split('(')[0].split('.')[-1]
    code_path = out_path+caller_name+'_'+method_hash[:16]+'.txt'
    # 根据caller得到要找的smali
    smali_path = f"{tmp_dir}/smali/{extract_class_name(caller)}.smali"
    i=1
    while not os.path.exists(smali_path):
        i+=1
        smali_path = f"{tmp_dir}/smali_classes{i}/{extract_class_name(caller)}.smali"
    # 打开对应smali文件，找到相应method
    with open(smali_path, 'r') as f:
        smali_content = f.readlines()
        out = parse_code(smali_content,parse_method_name(caller))
    with open(code_path,'a+') as f:
        f.write(out)
        f.write('\n')
    # shutil.rmtree(tmp_dir)
    return out

# 提取扰动
def con_clu_action_set(path):
    meta_fp = config['meta_data']
    with open(path,'r') as file:
        data = json.load(file)
    with open(meta_fp, "r") as f:
        meta = json.load(f)
        paths = [x['sample_path'] for x in meta]
    for i in range(10):
        call = []
        action = []
        lst = data[f"cluster{str(i)}"]
        for filename in lst:
            dir = f"{config['sfcg_dirs']}sfcg2gram/txt/"
            for x in paths:
                if filename.replace('.txt','') in x:
                    apk_path = x
                    break
            
            with open(os.path.join(dir,filename),'r') as file:
                lines = file.readlines()
                for line in lines:
                    if line not in call:
                        action.append(line.strip()+'->in:'+apk_path+'\n')
        call = []
        with open(f"{config['action_set']}cluster{i}.txt", "w") as f:
            # 将集合中的每个元素写入文件中
            for item in action:
                f.write(item)