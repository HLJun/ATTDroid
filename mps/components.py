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

# 从apk中提取组件
def extract_the_components_of_apk(apk_path):
    print("Process the APK: {}".format(os.path.basename(apk_path)))
    res_data = dict()
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        activities = a.get_activities()
        providers = a.get_providers()
        receivers = a.get_receivers()
        services = a.get_services()
        res_data["activities"] = activities
        res_data["providers"] = providers
        res_data["receivers"] = receivers
        res_data["services"] = services
        return res_data
    except:
        print("Error occurred in APK: {}".format(os.path.basename(apk_path)))
        traceback.print_exc()
        return None

# 判断是否是系统class
def is_system_class(name):
    system_packages = ["java.", "javax.", "android.", "androidx.", "dalvik.", "kotlin.", "kotlinx.", "junit.", "sun.",
                       "org.w3c.", "org.xmlpull.", "org.xml.", "org.json.", "org.apache.", "com.google.",
                       "com.android."]
    for package in system_packages:
        if name.startswith(package):
            return True
    return False


# 提取apk的指定组件
def slice_one_apk(apk, component_name, output_dir):
    apk_res_dir = config['source_apk_path']
    tmp_parent_dir = config['tmp_dir']
    apk_path = os.path.join(apk_res_dir, apk + ".apk")
    tmp_dir = tempfile.mkdtemp(dir=tmp_parent_dir)
    os.makedirs(tmp_dir, exist_ok=True)
    # 复制apk到tmp目录
    copy_apk_path = os.path.join(tmp_dir, os.path.basename(apk_path))
    shutil.copy(apk_path, copy_apk_path)

    jar = config['slicer']
    args = [component_name, copy_apk_path, output_dir, config['android_sdk']]
    print("Extracting the apk - {}, Component Name - {}".format(apk, component_name))
    out = run_java_component(jar, args, tmp_dir)
    if "Successfully" not in out:
        os.mkdir(os.path.join(output_dir, "failed"))
    shutil.rmtree(tmp_dir)


# 提取候选良性软件的组件
# 修改为提取候选良性软件的SFCG的函数调用关系
def get_candidate_benign_components(sampled_apk_num=100):
    show_logging(logging.INFO)
    # sample the benign apps to slice the benign components
    # 'meta_data': _project('train_data/apg/apg-meta-new-local.json'),
    with open(config['meta_data'], "r") as f:
        meta = json.load(f)
    benign_apk_paths = []
    for data in meta:
        # virustotal检测为0，标签年份为2018
        if int(data['vt_detection']) == 0 and str(data['year']) == "2018":
            benign_apk_paths.append(data['sample_path'])
    # 随机选择sampled_apk_num个
    benign_apk_paths = random.sample(benign_apk_paths, sampled_apk_num)
    services = set()
    providers = set()
    receivers = set()
    components_list = ["services", "providers", "receivers"]
    components_apk_map = dict()
    for component in components_list:
        components_apk_map[component] = dict()
    for apk in tqdm(benign_apk_paths):
        res_data = extract_the_components_of_apk(apk)
        for component in components_list:
            for component_class in res_data[component]:
                if is_system_class(component_class):
                    continue
                if component == "services":
                    services.add(component_class)
                elif component == "providers":
                    providers.add(component_class)
                else:
                    receivers.add(component_class)
                if components_apk_map[component].get(component_class) is None:
                    components_apk_map[component][component_class] = [os.path.basename(apk).split(".")[0]]
                else:
                    components_apk_map[component][component_class].append(os.path.basename(apk).split(".")[0])
    with open("./slices_candidates/candidates.json", "w") as f:
        json.dump(components_apk_map, f)
    print("The sample num: {}, The services: {}, providers: {}, receivers: {}".format(sampled_apk_num, len(services),
                                                                                      len(providers), len(receivers)))
    apk_list = []
    component_list = []
    output_list = []
    res_dir_path = config['slice_database']
    for component_type, value in components_apk_map.items():
        if not os.path.exists(os.path.join(res_dir_path, component_type)):
            os.mkdir(os.path.join(res_dir_path, component_type))
        for component_class_name, candidate_apks in value.items():
            if not os.path.exists(os.path.join(res_dir_path, component_type, component_class_name)):
                os.mkdir(os.path.join(res_dir_path, component_type, component_class_name))
            for apk in candidate_apks:
                if not os.path.exists(os.path.join(res_dir_path, component_type, component_class_name, apk)):
                    os.mkdir(os.path.join(res_dir_path, component_type, component_class_name, apk))
                slice_res_dir = os.path.join(res_dir_path, component_type, component_class_name, apk)

                # backup the benign apk to process
                apk_list.append(apk)
                component_list.append(component_class_name)
                output_list.append(slice_res_dir)

    with mp.Pool(processes=10) as p:
        p.starmap(slice_one_apk, zip(apk_list, component_list, output_list))


# 加载组件候选
def load_component_candidates():
    sliced_components = dict()
    sliced_components['services'] = dict()
    sliced_components['providers'] = dict()
    sliced_components['receivers'] = dict()

    with open("./slices_candidates/candidates.json", "r") as f:
        component_apk_dict = json.load(f)
    for component_type, value in component_apk_dict.items():
        for component_class_name, candidate_apks in value.items():
            for apk in candidate_apks:
                slice_res_dir = os.path.join(config['slice_database'], component_type, component_class_name, apk)
                if not os.path.exists(os.path.join(slice_res_dir, "failed")):
                    if sliced_components[component_type].get(component_class_name) is None:
                        sliced_components[component_type][component_class_name] = [apk]
                    else:
                        sliced_components[component_type][component_class_name].append(apk)
    return sliced_components
