import os
from .fcg import extract_fcg
from settings import config
import random
import json
from datasets.fcg import ex_sfcg,cluster2sfcg,mal_cluster,data2sfcg,txt2graph
from tqdm import tqdm

def contains_malware(string):
    keywords = ['MAL', 'MALWARE']
    for keyword in keywords:
        if keyword in string:
            return True
    return False

def append_to_json(file_path, data):
    # 如果文件不存在，则创建一个空文件
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            current_data = json.load(f)
    else:
        current_data = []
    # 将新数据追加到当前数据中
    current_data.extend(data)

    # 将新的数据写回文件
    with open(file_path, "w") as f:
        json.dump(current_data, f, indent=4)

def extract(dataset,meta_file):
    dir = config['source_apk_path']
    meta_data = []
    counter = 0
    thred = 100
    # 遍历
    for root, dirs, files in os.walk(dir):
        for filename in tqdm(files):
            if filename.endswith(".apk"):
                label = 0
                flag = True
                apk_path = os.path.join(root,filename)
                if contains_malware(apk_path):
                    label = 1
                fcg_path = f"{config['fcg_dirs']}{filename.replace('.apk','.txt')}"
                sfcg_txt_path = f"{config['sfcg_dirs']}sfcg2gram/txt/{filename.replace('.apk','.txt')}"
                sfcg_gml_path = f"{config['sfcg_dirs']}sfcg2gram/gml/{filename.replace('.apk','.graphmal')}"
                if not os.path.exists(fcg_path):
                    flag = extract_fcg(apk_path,fcg_path)
                if not os.path.exists(sfcg_txt_path) and flag:
                    flag = ex_sfcg(fcg_path,0,2)
                    # ex_sfcg(1,100)
                if not os.path.exists(sfcg_gml_path) and flag:
                    flag = txt2graph(sfcg_txt_path)
                if flag == False:
                    continue
                meta_data.append({"sample_path":apk_path,"dataset":f"{dataset}","fcg_path":fcg_path,"sfcg_txt_path":sfcg_txt_path,"sfcg_gml_path":sfcg_gml_path,"cluster":None,"label":label})
                counter+=1
                if counter == thred:
                    # 将数据写入 JSON 文件
                    append_to_json(meta_file,meta_data)
                    meta_data = []
                    counter = 0
    if len(meta_data) > 0:
        append_to_json(meta_file,meta_data)
    
def cluster(meta_file):
    meta_data = []
    with open(meta_file, "r") as f:
        meta_data = json.load(f)
    mals = [x for x in meta_data if x['label']==1]
    bens = [x for x in meta_data if x['label']==0]
    # 对恶意软件进行聚类
    mal_gml_paths = [item['sfcg_gml_path'] for item in mals]
    out_file = f"{config['sfcg_dirs']}10cluster_info.json"
    cluster_info_path = mal_cluster(mal_gml_paths,out_file,10,10)
    with open(cluster_info_path, "r") as json_file:
        cluster_info = json.load(json_file)
    # 更新回 meta_data 中
    
    for item in meta_data:
        if item['label']==1:
            cluster = cluster_info[item['sfcg_gml_path'].split('/')[-1].replace('.graphmal','')]
            item['cluster'] = cluster

    with open(meta_file, 'w') as f:
        json.dump(meta_data, f, indent=4)
     # 提取恶意软件和良性软件的sfcg相关信息的json
    bens_sfcg_path_list = [x['sfcg_txt_path'] for x in bens]
    mals_sfcg_path_list = [x['sfcg_txt_path'] for x in mals]
    data2sfcg(mals_sfcg_path_list,config['sfcg_dirs']+"/mal_sfcg.json")
    data2sfcg(bens_sfcg_path_list,config['sfcg_dirs']+"/ben_sfcg.json")
    # 提取恶意软件簇的sfcg相关信息的json
    cluster2sfcg(mals,cluster_info,10)
   

# 读取源数据集，提取APK基本信息和FCG
def prepare_dataset(dataset):
    meta_file = f"./train_data/{dataset}/{dataset}-meta.json"
    extract(dataset,meta_file)
    cluster(meta_file)
