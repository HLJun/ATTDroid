import os
from settings import config
import ujson as json
from models.drebin import get_drebin_feature
from models.apigraph import get_apigrah_feature
from models.mamadroid import get_mamadroid_feature
from models.vae_fd import get_vae_fd_feature
import multiprocessing as mp
from itertools import repeat
from utils import red
from androguard.core.androconf import show_logging
import logging
from tqdm import tqdm
import numpy as np
import random


class APK:
    """The APK data for feature extracting"""

    # def __init__(self, path, label, t):
    def __init__(self, path, sfcg_txt_path,cluster,label):
        self.name = os.path.basename(path)
        self.location = path
        self.sfcg_txt_path = sfcg_txt_path
        self.sfcg_apis = []
        self.sfcg_callers = []
        self.calls = []
        self.cluster = cluster
        self.label = label
        # self.t = t  # The time of the APKs
        # 特征路径
        self.drebin_feature_path = os.path.join(config['saved_features'], 'drebin', self.name + ".json")
        self.apigraph_feature_path = os.path.join(config['saved_features'], 'apigraph', self.name + ".json")
        self.mamadroid_feature_path = os.path.join(config['saved_features'], 'mamadroid', self.name + ".npz")
        self.vae_fd_feature_path = os.path.join(config['saved_features'], 'vae_fd', self.name + ".npz")
        # 特征
        self.drebin_feature = None
        self.apigraph_feature = None
        self.mamadroid_family_feature = None
        self.vae_fd_feature = None
        self.get_ori_apis()
    def get_ori_apis(self):
        if os.path.exists(self.sfcg_txt_path):
            with open(self.sfcg_txt_path,'r') as file:
                calls = list(set([line.strip() for line in file.readlines()]))
                self.calls = calls
                for call in calls:
                    self.sfcg_apis.extend(call.split('--->'))
                    self.sfcg_callers.append(call.split('--->')[0])
        else:
            logging.info("Error! Wrong sfcg_txt_path.")

    def get_drebin_feature(self):
        """Extract the drebin feature"""
        if os.path.exists(self.drebin_feature_path):
            logging.info("Load APK: {}, drebin feature from file {}".format(self.name, self.drebin_feature_path))
            with open(self.drebin_feature_path, "rt") as f:
                self.drebin_feature = json.load(f)
        else:
            self.drebin_feature = get_drebin_feature(self.location, self.drebin_feature_path)

    def get_apigraph_feature(self):
        """Extract the apigraph feature"""
        if os.path.exists(self.apigraph_feature_path):
            logging.info("Load APK: {}, apigraph feature from file {}".format(self.name, self.apigraph_feature_path))
            with open(self.apigraph_feature_path, "rt") as f:
                self.apigraph_feature = json.load(f)
        else:
            self.apigraph_feature = get_apigrah_feature(self.location, self.apigraph_feature_path)

    def get_mamadroid_feature(self):
        """Extract the mamadroid feature"""
        if os.path.exists(self.mamadroid_feature_path):
            logging.info("Load APK: {}, mamadroid feature from file {}".format(self.name, self.mamadroid_feature_path))
            data = np.load(self.mamadroid_feature_path)
            self.mamadroid_family_feature = data['family_feature']
        else:
            self.mamadroid_family_feature = get_mamadroid_feature(self.location, self.mamadroid_feature_path)

    def get_vae_fd_feature(self):
        """Extract the vae_fd feature"""
        if os.path.exists(self.vae_fd_feature_path):
            logging.info("Load APK: {}, vae_fd feature from file {}".format(self.name, self.vae_fd_feature_path))
            data = np.load(self.vae_fd_feature_path)
            self.vae_fd_feature = data['vae_fd_feature']
        else:
            self.vae_fd_feature = get_vae_fd_feature(self.location,
                                                     self.vae_fd_feature_path)


class APKSET:
    """The Dataset for training the malware detection methods"""

    def __init__(self, meta_fp, name):
        self.name = name
        self.meta = None
        self.label = None
        self.total_set = []
        self.test_set = []
        self.train_idxs = []
        self.test_idxs = []
        self.load_data(meta_fp)
        self.malscan_feature_vector = None

    def load_data(self, meta_fp):
        """Loading the total dataset"""
        with open(meta_fp, "r") as f:
            self.meta = json.load(f)
            random.shuffle(self.meta)
            self.label = [x['label'] for x in self.meta]

        # with open(label_fp, "r") as f:
        #     self.label = json.load(f)

        for sample in zip(self.meta, self.label):
            # 不包含时间
            self.total_set.append(APK(sample[0]['sample_path'], sample[0]['sfcg_txt_path'], sample[0]['cluster'], sample[1]))
            # self.total_set.append(APK(sample[0]['sample_path'], sample[1], "-".join(
            #     [str(sample[0]['year']), "{:0>2d}".format(int(sample[0]['month'])),
            #      "{:0>2d}".format(int(sample[0]['day']))])))

    def split_the_dataset(self):
        """Split the dataset by time"""
        # 如果数据集是apg
        if self.name == "apg":
            for idx, apk in enumerate(self.total_set):
                # 非2018年的数据作为训练集，2018年得数据作为测试集
                if apk.t.split('-')[0] != "2018":
                    self.train_idxs.append(idx)
                else:
                    self.test_idxs.append(idx)
                    self.test_set.append(apk)
        
        else:
            # 获取总数据集长度
            total_length = len(self.total_set)
            # 计算测试集长度（20%）
            test_length = int(total_length * 0.2)
            # 创建索引列表并打乱顺序
            indices = list(range(total_length))
            random.shuffle(indices)
            # 将前20%的索引分配给测试集，其余的分配给训练集
            self.test_idxs = indices[:test_length]
            self.train_idxs = indices[test_length:]
            # 根据索引列表获取相应的数据集
            self.test_set = [self.total_set[idx] for idx in self.test_idxs]

    def extract_the_feature(self, method):
        """Extract the training dataset feature"""
        if method == "mamadroid" or method == "vae_fd":
            if config['extract_feature']:
                show_logging(logging.INFO)

        unprocessed_apk_set = []
        # 没有提取特征的apk集合
        for apk in self.total_set:
            if method == "drebin":
                if not os.path.exists(apk.drebin_feature_path):
                    unprocessed_apk_set.append(apk)
            elif method == "apigraph":
                if not os.path.exists(apk.apigraph_feature_path):
                    unprocessed_apk_set.append(apk)
            elif method == "mamadroid":
                if not os.path.exists(apk.mamadroid_feature_path):
                    unprocessed_apk_set.append(apk)
            elif method == "vae_fd":
                if not os.path.exists(apk.vae_fd_feature_path):
                    unprocessed_apk_set.append(apk)
        # 提取未处理的apk的特征
        with mp.Pool(processes=config['nproc_feature']) as p:
            p.starmap(get_feature_wrapper, zip(unprocessed_apk_set, repeat(method)))

    # 将单独提取的apk特征整合到total_data
    def collect_the_feature(self, method):
        """Collect the features of all APKs into a single file for loading"""
        total_feature_fn = os.path.join(config['saved_features'], method + "_total", method + "_total_feature.json")
        if os.path.exists(total_feature_fn):
            return
        total_data = dict()
        dirname = os.path.join(config['saved_features'], method)
        apks = os.listdir(dirname)
        apks = sorted(apks)
        for apk in tqdm(apks):
            if method == "apigraph" or method == "drebin":
                with open(os.path.join(dirname, apk), "r") as f:
                    data = json.load(f)
                    total_data[apk] = data
            elif method == "mamadroid":
                data = np.load(os.path.join(dirname, apk))
                if True not in np.isnan(data['family_feature']):
                    total_data[apk] = data['family_feature'].tolist()
            else:
                data = np.load(os.path.join(dirname, apk))
                total_data[apk] = data['vae_fd_feature'].tolist()
        with open(total_feature_fn, "w") as f:
            json.dump(total_data, f)

    # load上个函数整合的特征
    def load_the_feature(self, method):
        """Load the feature"""
        total_feature_fn = os.path.join(config['saved_features'], method + "_total", method + "_total_feature.json")
        if not os.path.exists(total_feature_fn):
            logging.error(red("The total feature is not exist, please extract the feature!"))
            exit(0)
        with open(total_feature_fn, "r") as f:
            total_feature = json.load(f)
        if method == "drebin":
            for apk in tqdm(self.total_set):
                apk.drebin_feature = total_feature[apk.name + ".json"]
        elif method == "mamadroid":
            for apk in tqdm(self.total_set):
                apk.mamadroid_family_feature = total_feature[apk.name + ".npz"]
        elif method == "apigraph":
            for apk in tqdm(self.total_set):
                apk.apigraph_feature = total_feature[apk.name + ".json"]
        elif method == "vae_fd":
            for apk in tqdm(self.total_set):
                apk.vae_fd_feature = total_feature[apk.name + ".npz"]

# 根据method参数提取apk的特征
def get_feature_wrapper(apk, method):
    """Wrapper function for parallel feature extraction"""
    if method == "drebin":
        apk.get_drebin_feature()
    elif method == "mamadroid":
        apk.get_mamadroid_feature()
    elif method == "apigraph":
        apk.get_apigraph_feature()
    elif method == "vae_fd":
        apk.get_vae_fd_feature()
