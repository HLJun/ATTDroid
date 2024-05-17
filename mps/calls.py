import os
import json
import random
import shutil
import traceback
import multiprocessing as mp
from androguard.misc import AnalyzeAPK
from settings import config
import tempfile
from utils import run_java_component
from androguard.core.androconf import show_logging
import logging
from tqdm import tqdm
from datasets.fcg import find_cluster_sim_ben,con_clu_action_set
# from ..datasets.fcg import ex_sfcg,mal_cluster
from utils import blue, green, red

def get_candidate_benign_calls(sample_rate=0.2,cluster_num=10):
    mal_sfcg_json_dir = config['sfcg_dirs']
    ben_sfcg_json_path = f"{config['sfcg_dirs']}/ben_sfcg.json"
    # 找到最相似的良性软件集
    out_path = f"{config['saved_jsons']}/sim_bens.json"
    find_cluster_sim_ben(ben_sfcg_json_path,mal_sfcg_json_dir,out_path,sample_rate=0.2)
    # 提取它们的函数调用集合
    con_clu_action_set(out_path)