import random
from settings import config
import argparse
import os
import utils
import shutil
import logging
import numpy as np
from utils import blue, green, calculate_base_metrics
import multiprocessing as mp
from pprint import pformat
from itertools import repeat
from datasets.apks import APKSET
from models.detector import Detector
from attacker.adz import AdvDroidZero_attacker
from androguard.core.androconf import show_logging
from mps.calls import get_candidate_benign_calls
from datasets.pre import prepare_dataset
from attacker.rs import RandomPerturbationSelector
import json
from concurrent.futures import ThreadPoolExecutor
import threading
random.seed(42)


def main():
    args = parse_args()
    utils.configure_logging(args.run_tag, args.debug)
    # 准备好输出路径
    output_result_dir = prepare_res_save_dir(args)

    # STAGE - Building the Malware Detection Methods
    logging.info(blue('Begin Stage ------- Building the Malware Detection Methods'))
    logging.info(green('Load the apk data...'))

    # 如果参数包含prepare，对数据集进行预处理后退出
    if config['prepare_dataset']:
        logging.info(green(f'Firstly load dataset {args.dataset}...'))
        prepare_dataset(args.dataset)
        exit() 

    dataset = APKSET(config['meta_data'], args.dataset)

    logging.info(green('Split the data set...'))
    dataset.split_the_dataset()

    # Extract the feature
    if config['extract_feature']:
        logging.info(green('Extract the apk feature...'))
        dataset.extract_the_feature(args.detection)
        exit()

    logging.info(green('Load the apk feature...'))
    dataset.collect_the_feature(args.detection)
    dataset.load_the_feature(args.detection)

    logging.info(green('Train the target model...'))
    model = Detector("_".join([args.detection, args.dataset, args.classifier]), config['saved_models'],
                    args.detection, args.classifier)

    model.build_classifier(dataset)

    logging.info(green('Test the target model...'))
    y_pred = None
    y_scores = None
    if args.classifier == "svm":
        y_pred = model.clf.predict(model.X_test)  # The decision boundary of SVM is 0
        y_scores = model.clf.decision_function(model.X_test)
        with open('scores.txt','w') as f:
            y_scores_str = json.dumps(y_scores.tolist()) 
            f.write(y_scores_str)
    elif args.classifier == "mlp":
        y_pred = model.clf.predict(model.X_test)
        y_scores = model.clf.predict_proba(model.X_test)
    elif args.classifier == "rf":
        y_pred = model.clf.predict(model.X_test)
        y_scores = model.clf.predict_proba(model.X_test)
        with open('scores.txt','w') as f:
            y_scores_str = json.dumps(y_scores.tolist()) 
            f.write(y_scores_str)
    elif args.classifier == "3nn":
        y_pred = model.clf.predict(model.X_test)
        y_scores = model.clf.predict_proba(model.X_test)
    elif args.classifier == "fd_vae_mlp":
        y_pred = model.clf.predict(model.X_test, threshold=30)
        y_scores = model.clf.predict_proba(model.X_test, threshold=30)

    assert y_pred is not None
    
    # 预测正确的test恶意样本
    tps = np.where((model.y_test & y_pred) == 1)[0]
    tp_apks = [dataset.test_set[i] for i in tps]
    with open('/home/hlj/code/android/code/ATTDroid/model_results/cic20/jsons/backup/'+'predict_right_malwares_rf.txt','w') as file:
        for apk in tp_apks:
            file.write(apk.location+'\n')

    # 计算评价指标
    report = calculate_base_metrics(model, y_pred, y_scores)
    report['number_of_apps'] = {'train': len(model.y_train),
                                'test': len(model.y_test),
                                'tps': len(tp_apks)}

    # logging.info(blue('Performance before attack:\n' + pformat(report)))
    print('Performance before attack:\n' + pformat(report))

    # random sample malware
    # 从预测正确的样本中随机选择恶意软件
    # if len(tp_apks) > args.attack_num:
    #     tp_apks = random.sample(tp_apks, args.attack_num)
    

    # 如果参数包含train_model
    if args.train_model:
        exit()

    # STAGE - Creating the Malware Perturbation Set
    # 重点 修改为自己的代码
    if args.create_mps:
        get_candidate_benign_calls()
        exit()

    # STAGE - Victim Model Querying
    if args.ATT_attack:
        logging.info(blue('Begin Stage ------- Victim Model Querying Attack'))
        show_logging(logging.INFO)
        # 构建一个全局的随机扰动选择器
        ps = RandomPerturbationSelector()
        
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.CRITICAL)
        # 创建一个FileHandler,用于写入日志文件
        file_handler = logging.FileHandler('attack.log')
        # 设置文件日志格式
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        # 添加文件日志处理器
        logger.addHandler(file_handler)
        if config['serial']:
            for apk in tp_apks:
                AdvDroidZero_attacker(apk, model, args.attack_num, output_result_dir,ps,logger)
        else: 
            print(len(tp_apks))
            # with ThreadPoolExecutor(max_workers=config['nproc_attacker']) as executor:
            #     executor.map(AdvDroidZero_attacker,
            #               zip(tp_apks, repeat(model), repeat(args.attack_num), repeat(output_result_dir),repeat(ps)))
            with mp.Pool(processes=config['nproc_attacker']) as p:
                p.starmap(AdvDroidZero_attacker,
                          zip(tp_apks, repeat(model), repeat(args.attack_num), repeat(output_result_dir),repeat(ps),repeat(logger)))


def prepare_res_save_dir(args):
    """ Prepare the attack result saving dir """
    # 准备好攻击结果的保存路径
    # Malware Detection Model Saving Dir
    if not os.path.exists(config['saved_models']):
        os.makedirs(config['saved_models'], exist_ok=True)

    if not os.path.exists(config['saved_features']):
        os.makedirs(config['saved_features'], exist_ok=True)
    if not os.path.exists(os.path.join(config['saved_features'], 'drebin')):
        os.makedirs(os.path.join(config['saved_features'], 'drebin'), exist_ok=True)
    if not os.path.exists(os.path.join(config['saved_features'], 'drebin_total')):
        os.makedirs(os.path.join(config['saved_features'], 'drebin_total'), exist_ok=True)
        if not os.path.exists(os.path.join(config['saved_features'], 'apigraph')):
            os.makedirs(os.path.join(config['saved_features'], 'apigraph'), exist_ok=True)
    if not os.path.exists(os.path.join(config['saved_features'], 'apigraph_total')):
        os.makedirs(os.path.join(config['saved_features'], 'apigraph_total'), exist_ok=True)
    if not os.path.exists(os.path.join(config['saved_features'], 'mamadroid')):
        os.makedirs(os.path.join(config['saved_features'], 'mamadroid'), exist_ok=True)
    if not os.path.exists(os.path.join(config['saved_features'], 'mamadroid_total')):
        os.makedirs(os.path.join(config['saved_features'], 'mamadroid_total'), exist_ok=True)
    if not os.path.exists(os.path.join(config['saved_features'], 'vae_fd')):
        os.makedirs(os.path.join(config['saved_features'], 'vae_fd'), exist_ok=True)
    if not os.path.exists(os.path.join(config['saved_features'], 'vae_fd_total')):
        os.makedirs(os.path.join(config['saved_features'], 'vae_fd_total'), exist_ok=True)
    
    if not os.path.exists(os.path.join(config['dataset_data'], args.dataset)):
        os.makedirs(os.path.join(config['dataset_data'], args.dataset), exist_ok=True)

    if not os.path.exists(os.path.join(config['fcg_dirs'], args.dataset)):
        os.makedirs(os.path.join(config['fcg_dirs'], args.dataset), exist_ok=True)

    if not os.path.exists(os.path.join(config['sfcg_dirs'], args.dataset)):
        os.makedirs(os.path.join(config['sfcg_dirs'], args.dataset), exist_ok=True)

    output_result_dir = os.path.join(config['results_dir'], args.dataset,
                                     "_".join([args.detection, args.classifier]),
                                     "_".join([args.attacker, str(args.attack_num)]))
    if not os.path.exists(output_result_dir):
        os.makedirs(output_result_dir, exist_ok=True)
    else:
        shutil.rmtree(output_result_dir)
        os.makedirs(output_result_dir, exist_ok=True)

    # Save the success misclassified malicious APKs
    if not os.path.exists(os.path.join(output_result_dir, "success")):
        os.mkdir(os.path.join(output_result_dir, "success"))

    # Save the fail misclassified malicious APKs
    if not os.path.exists(os.path.join(output_result_dir, "fail")):
        os.mkdir(os.path.join(output_result_dir, "fail"))

    # Save the malicious APKs which cannnot be modified
    if not os.path.exists(os.path.join(output_result_dir, "modification_crash")):
        os.mkdir(os.path.join(output_result_dir, "modification_crash"))

    return output_result_dir


def parse_args():
    p = argparse.ArgumentParser()

    # Experiment variables
    p.add_argument('-R', '--run-tag', help='An identifier for this experimental setup/run.')
    p.add_argument('--train_model', action='store_true', help="The training process of the malware detection method.")
    p.add_argument('--create_mps', action='store_true', help="The creating process of the malware perturbation set.")

    # Choose the target android dataset
    p.add_argument('--dataset', type=str, default="cic20", help='The target malware dataset.')

    # Choose the target feature extraction method
    p.add_argument('--detection', type=str, default="drebin", help='The target malware feature extraction method.')

    # Choose the target classifier
    p.add_argument('--classifier', type=str, default="svm", help='The target malware classifier.')

    # Choose the attack method
    p.add_argument('--attacker', type=str, default="ATTDroid", help='The attack method.')

    # Attackers
    p.add_argument('--ATT_attack', action='store_true', help='The ATTDroid Attack.')
    p.add_argument('-N', '--attack_num', type=int, default=100, help='The query budget.')

    # Misc
    p.add_argument('-D', '--debug', action='store_true', help='Display log output in console if True.')

    # 提取SFCG的方法
    p.add_argument('--sfcg',type=str, default="ngrams", help='The target malware feature extraction method.')
    p.add_argument('--sfcg_num', type=int, default=2, help='The target malware feature extraction method.')

    args = p.parse_args()

    return args


if __name__ == '__main__':
    main()
