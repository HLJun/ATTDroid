import os
import shutil
import logging
import tempfile
import numpy as np
import random
import time
import traceback
from settings import config
from androguard.misc import AnalyzeAPK
from models.drebin import get_drebin_feature
from models.apigraph import get_apigrah_feature
from models.mamadroid import get_mamadroid_feature
from models.vae_fd import get_vae_fd_feature
from attacker.pst import PerturbationSelectionTree
from utils import sign_apk
from utils import green, red
from utils import run_java_component
from datasets.fcg import get_code


def get_basic_info(apk_path):
    results = dict()
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        # get the apk version
        min_api_version = a.get_min_sdk_version()
        max_api_version = a.get_max_sdk_version()
        if min_api_version is None:
            min_api_version = 1
        if max_api_version is None:
            max_api_version = 1000
        results["min_api_version"] = int(min_api_version)
        results["max_api_version"] = int(max_api_version)

        # get the uses-features
        results["uses-features"] = set(a.get_features())

        # get the permissions
        results["permissions"] = set(a.get_permissions())

        # get the intent actions
        intent_actions = []
        for node in a.get_android_manifest_xml().findall(".//action"):
            for key, value in node.attrib.items():
                intent_actions.append(value)
        for node in a.get_android_manifest_xml().findall(".//category"):
            for key, value in node.attrib.items():
                intent_actions.append(value)
        results["intents"] = set(intent_actions)
    except:
        logging.error(red("Error occurred in APK: {}".format(os.path.basename(apk_path))))
        traceback.print_exc()
        return None

    return results

type_map = {
        "void": "V", 
        "boolean": "Z",
        "byte": "B",
        "short": "S", 
        "char": "C",
        "int": "I",
        "long": "J",
        "float": "F",
        "double": "D",
        "String": "Ljava/lang/String;"
}

def extract_class_name(string):
    return '/'.join(string.split('(')[0].split(".")[0:-1])

def parse_api_string(api_string):
    # 分割字符串获取类名、方法名和参数
    str1 = api_string.split('(')[0]
    str2 = api_string.split(')')[1]
    params = api_string.split('(')[1].split(')')[0]
    params_f = ""
    if params != "":
        params = params.split(',')
        for p in params:
            out = ""
            if p.startswith('['):
                p = p[1:]
                out += '['
            if p in type_map:
                out += type_map[p]
            else:
                out += 'L'+p+';'
            params_f += out
    params_f = params_f.replace('.','/')
    pack = extract_class_name('L'+str1)
    method = str1.split('.')[-1]
    out = ""
    if str2.startswith('['):
        str2 = str2[1:]
        out += '['
    if str2 in type_map:
        out += type_map[str2]
    else:
        out += 'L'+str2+';'
    return_type = out.replace('.','/')
    
    # 根据获取的信息构建新的格式
    new_format = f"{pack};->{method}({params_f}){return_type}"
    return new_format

# 解压 APK，要攻击的apk
def extract_apk(apk_path, extract_dir):
    cmd = "apktool d "+apk_path+" -o "+extract_dir+" -r -f"
    os.system(cmd)


# 在 smali 文件中插入新代码
def insert_line(smali_dir,caller,callee):
    print(f"callee{callee}")
    print(f"caller{caller}")
    # 编写新的 smali 代码
    new_code = f'''
    invoke-static {{}}, {parse_api_string(callee)}
'''
    # smali 方法的标识符，用于定位到方法的开始和结束位置
    method_identifier = parse_api_string(caller).split('->')[1]
    # 找到一个原本就存在的 API 调用点，并确定插入新代码的位置
    # 在这里你需要编写代码来找到合适的插入点
    smali_path = f"{smali_dir}/smali/{extract_class_name(caller)}.smali"
    if not os.path.exists(smali_path):
        smali_path = f"{smali_dir}/smali_classes2/{extract_class_name(caller)}.smali"
    with open(smali_path, 'r') as f:
        smali_content = f.readlines()
    start_index = None
    end_index = None

    # 查找方法的开始和结束位置
    for i, line in enumerate(smali_content):
        if method_identifier in line and '.method' in line:
            start_index = i
        if start_index is not None and ".end method" in line:
            end_index = i
            break

    if start_index is not None and end_index is not None:
        # 将新代码逐行添加，并根据缩进格式进行缩进
        for code_line in new_code.split('\n'):
            if code_line.strip():  # 跳过空行
                smali_content.insert(end_index, '\n'+code_line)
                end_index += 1  # 更新结束位置
        # 插入一个空行
        smali_content.insert(end_index, '\n\n')
        end_index += 2  # 更新结束位置
        # 将修改后的内容写回文件
        with open(smali_path, 'w') as f:
            f.writelines(smali_content)
        print("Insert a invoke line sussessfully!")
    else:
        print("Cannot find the method!")

def sign_apk(apk_path):
    cmd = f"java -jar {config['resigner']} --overwrite -a {apk_path} "
    os.system(cmd)

# 重新打包 APK
def repack_apk(apk_dir, output_apk):
    command = f"apktool b {apk_dir} -o {output_apk}"
    os.system(command)
    sign_apk(output_apk)

def insert_invoke(action,parse_tmp, copy_apk_path,backup_dir,process_dir):
    try:
        # copy apk to backup dir
        shutil.copy(copy_apk_path, os.path.join(backup_dir, os.path.basename(copy_apk_path)))
        os.makedirs(parse_tmp, exist_ok=True)
        # 在 smali 文件中插入新代码
        insert_line(parse_tmp,action.caller,action.callee)
        # 重新打包 APK
        repack_apk(parse_tmp, os.path.join(process_dir,os.path.basename(copy_apk_path)))
        print("Insert a invoke successfully")
        return True
    except Exception as e:
        print(f"Error in insert_invoke:{e}")
        traceback.print_exc()
        return False

def get_smali(action):
    # action对应的apk的解析位置
    tmp_dir = f"/home/hlj/dev/shm/gnip/smali/{os.path.basename(action.apk_path.strip()).replace('.apk','')}/"
    if not os.path.exists(tmp_dir):
        cmd = f"apktool d {action.apk_path.strip()} -o {tmp_dir} -r -f"
        os.system(cmd)
    smali_path = f"{tmp_dir}/smali/{extract_class_name(action.caller)}.smali"
    i=1
    try:
        while not os.path.exists(smali_path):
            i+=1
            if i>100:
                raise Exception(f"Error {smali_path}")
            print(f"{tmp_dir}/smali_classes{i}/{extract_class_name(action.caller)}.smali")
            smali_path = f"{tmp_dir}/smali_classes{i}/{extract_class_name(action.caller)}.smali"
    except Exception as e:
        print(f"Error in get_smali:{e}")
        traceback.print_exc()
        return False
        
    # 打开对应smali文件，找到相应method
    with open(smali_path, 'r') as f:
        smali_content = f.readlines()
    if not os.path.exists(f"/data/hlj/datas/cic20/code/{action.cluster}/"):
        os.makedirs(f"/data/hlj/datas/cic20/code/{action.cluster}/")
    with open(f"/data/hlj/datas/cic20/code/{action.cluster}/{action.caller}.txt",'w') as file:
        file.writelines(smali_content)
        # smali_content = smali_content[3:]
    return smali_content

def insert_smali(ori_caller,action,parse_tmp,copy_apk_path,backup_dir,process_dir):
    try:
        # copy apk to backup dir
        shutil.copy(copy_apk_path, os.path.join(backup_dir, os.path.basename(copy_apk_path)))
        os.makedirs(parse_tmp, exist_ok=True)
        # 在 smali 文件中插入新代码
        insert_smali_imp(parse_tmp,ori_caller,action)
        # 重新打包 APK
        repack_apk(parse_tmp, os.path.join(process_dir,os.path.basename(copy_apk_path)))
        print("Insert a smali successfully")
        return True
    except Exception as e:
        print(f"Error in insert_smali:{e}")
        traceback.print_exc()
        return False

def load_smali(action):
    with open(action.smali_apth,'r') as file:
        return file.readlines()

def insert_smali_imp(parse_dir,ori_caller,action):
    print(ori_caller)
    print(action.caller)
    smali_content = ""
    if action.smali != None:
        smali_content = action.smali
    elif os.path.exists(action.smali_path):
        smali_content = load_smali(action)
    else:
        smali_content = get_smali(action)
        # smali_content = get_code(apk_path,action.caller,action.cluster)
        action.smali = smali_content

    # smali_content = get_smali(apk_path,action.caller)

    dir = '/'.join(action.caller.split('(')[0].split('.')[:-2])
    name = action.caller.split('(')[0].split('.')[-2]
    new_api = action.caller
    new_smali_path = f'{parse_dir}/smali/{dir}/{name}.smali'
    if not os.path.exists(os.path.join(parse_dir+'/smali',dir)):
        os.makedirs(os.path.join(parse_dir+'/smali',dir),exist_ok=True)
    else:
        i=1
        new_smali_path = f'{parse_dir}/smali/{dir}/{name}${i}.smali'
        while os.path.exists(new_smali_path):
            print(f'{parse_dir}/smali/{dir}/{name}${i}.smali')
            i+=1 
            new_smali_path = f'{parse_dir}/smali/{dir}/{name}${i}.smali'
            new_api = f"{action.caller.split('(')[0]}${i}({action.caller.split('(')[1]}"
        smali_content[0] = smali_content[0].replace(';',f"${i};")
    # new_smali_path = f'{parse_dir}/smali/{dir}/{name}.smali'
    with open(new_smali_path,'w') as file:
        file.writelines(smali_content)
    insert_line(parse_dir,ori_caller,new_api)


def get_method(method_path,caller,callee):
    with open(method_path,'r') as file:
        lines = file.readlines()
        method_identifier = parse_api_string(caller.split('.')[-1]).split('->')[1]
        method = ""
        start = False
        for line in lines:
            if method_identifier in lines and '.method' in line:
                start = True
            if start==True:
                method+=line
            if '.end method' in line:
                start = False
                if parse_api_string(callee.split('.')[-1]).split('->')[1] in method:
                    return method
                method = ""

def insert_code(smali_dir, ori_caller, node):
    method = ""
    if node.method != None:
        method = node.method
    elif os.path.exists(node.method_path):
        method = get_method(node.method_path,node.caller,node.callee)
    else:
        apk_path = node.apk_path
        method = get_code(apk_path,node.caller,node.cluster)
        node.method = method
    # 现有api节点调用caller
    new_code = f'''
    invoke-static {{}}, {parse_api_string(node.caller)}
'''
    # smali 方法的标识符，用于定位到方法的开始和结束位置
    method_identifier = parse_api_string(ori_caller).split('->')[1]
    # 找到一个原本就存在的 API 调用点，并确定插入新代码的位置
    # 在这里你需要编写代码来找到合适的插入点
    smali_path = f"{smali_dir}/smali/{extract_class_name(ori_caller)}.smali"
    i=1
    while not os.path.exists(smali_path):
        print(f"{smali_dir}/smali_classes{i}/{extract_class_name(ori_caller)}.smali")
        print("insert code")
        i+=1
        smali_path = f"{smali_dir}/smali_classes{i}/{extract_class_name(ori_caller)}.smali"
    with open(smali_path, 'r') as f:
        smali_content = f.readlines()
    start_index = None
    end_index = None

    # 查找方法的开始和结束位置
    for i, line in enumerate(smali_content):
        if method_identifier in line and '.method' in line:
            start_index = i
        if start_index is not None and ".end method" in line:
            end_index = i
            break
    if start_index is not None and end_index is not None:
        # 在结束位置之后插入新的方法定义
        smali_content.insert(end_index,new_code)
        end_index += 1
        smali_content.insert(end_index + 2, '\n\n')
        end_index += 2
        # 将新代码逐行添加，并根据缩进格式进行缩进
        for code_line in method.split('\n'):
            if code_line.strip():  # 跳过空行
                smali_content.insert(end_index + 1, code_line + '\n')
                smali_content.insert(end_index + 2, '\n')
                end_index += 2
        # 将修改后的内容写回文件
        with open(smali_path, 'w') as f:
            f.writelines(smali_content)
        print("代码插入成功！")
    else:
        print("未找到指定方法！")
  
def insert_method(api,action,parse_tmp, copy_apk_path,backup_dir,process_dir):
    try:
        # copy apk to backup dir
        shutil.copy(copy_apk_path, os.path.join(backup_dir, os.path.basename(copy_apk_path)))
        os.makedirs(parse_tmp, exist_ok=True)
        # 解压 APK
        extract_apk(copy_apk_path, parse_tmp)
        # 在 smali 文件中插入新代码
        insert_code(parse_tmp,api,action)
        # 重新打包 APK
        repack_apk(parse_tmp, os.path.join(process_dir,os.path.basename(copy_apk_path)))
        print("APK 修改成功！")
        return True
    except Exception as e:
        print(f"An error occurred insert_method: {e}")
        traceback.print_exc()
        return False


def execute_action(action, tmp_dir, apk_path, inject_activity_name, inject_receiver_name, inject_receiver_data):
    backup_dir = os.path.join(tmp_dir, "backup")
    process_dir = os.path.join(tmp_dir, "process")
    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(process_dir, exist_ok=True)

    if os.path.exists(os.path.join(tmp_dir, "AndroidManifest.xml")):
        os.remove(os.path.join(tmp_dir, "AndroidManifest.xml"))

    # copy apk to backup dir
    shutil.copy(apk_path, os.path.join(backup_dir, os.path.basename(apk_path)))

    if action[1].name == "AndroidManifest.xml":
        jar = config['manifest']
        if action[2].name == "uses-features":
            modificationType = "feature"
        elif action[2].name == "permission":
            modificationType = "permission"
        else:
            if action[3].name == "activity_intent":
                modificationType = "activity_intent"
            elif action[3].name == "broadcast_intent":
                modificationType = "broadcast_intent"
            else:
                modificationType = "intent_category"
        args = [apk_path, process_dir, config['android_sdk'], modificationType, ";".join(action[-1].name),
                inject_activity_name, inject_receiver_name, inject_receiver_data]
    else:
        jar = config['injector']
        args = [apk_path, action[-1].name[0], action[2].name,
                os.path.join(config['slice_database'], action[2].name + "s", action[-1].name[0],
                             random.choice(action[-1].name[1])), process_dir, config['android_sdk']]

    # run program modification java code to execute the action
    res = run_java_component(jar, args, tmp_dir)
    return res, backup_dir, process_dir


def AdvDroidZero_attacker(apk, model, query_budget, output_result_dir,perturbation_selector,logger):
    if os.path.exists(os.path.join(output_result_dir, "fail", apk.name.split('.')[0])):
        print(f"{apk.name} already being attacked.\n")
        return 
    if os.path.exists(os.path.join(output_result_dir, "success", apk.name.split('.')[0])):
        print(f"{apk.name} already being attacked.\n")
        return 
    if os.path.exists(os.path.join(output_result_dir, "modification_crash", apk.name.split('.')[0])):
        print(f"{apk.name} already being attacked.\n")
        return 
    out = ""
    logging.info(green('Begin Attacking APK:{}'.format(apk.name)))
    out+='Begin Attacking APK:{}\n'.format(apk.name)
    # 准备好被攻击apk的特征
    victim_feature = None
    if model.feature == "drebin":
        victim_feature = model.vec.transform(apk.drebin_feature)
    elif model.feature == "apigraph":
        victim_feature = model.vec.transform(apk.apigraph_feature)
    elif model.feature == "mamadroid":
        victim_feature = np.expand_dims(apk.mamadroid_family_feature, axis=0)
    elif model.feature == "vae_fd":
        victim_feature = apk.vae_fd_feature

    assert victim_feature is not None
    # 原本的标签
    source_label = model.clf.predict(victim_feature)
    source_confidence = None
    if model.classifier == "svm":
        source_confidence = model.clf.decision_function(victim_feature)
    elif model.classifier == "mlp":
        source_confidence = model.clf.predict_proba(victim_feature)[0][1]
    elif model.classifier == "rf":
        source_confidence = model.clf.predict_proba(victim_feature)[0][1]
    elif model.classifier == "3nn":
        source_confidence = model.clf.predict_proba(victim_feature)[0][1]
    elif model.classifier == "fd_vae_mlp":
        source_confidence = model.clf.predict_proba(victim_feature)[0][1]
        source_label = source_confidence
    assert source_confidence is not None
    prev_confidence = source_confidence
    # 如果是良性软件，退出
    if source_label == 0:
        logging.info(red("APK was predicted to be benign ----- APK: {}".format(apk.name)))
        out+="APK was predicted to be benign ----- APK: {}\n".format(apk.name)
        # logger.critical(red("APK was predicted to be benign ----- APK: {}".format(apk.name)))
        return
    else:
        logging.info(green("Original confidence: {} ----- APK: {}".format(source_confidence,apk.name)))
        out+="Original confidence: {} ----- APK: {}\n".format(source_confidence,apk.name)
        # logger.critical(green("Original confidence: {} ----- APK: {}".format(source_confidence,apk.name)))

    # get the basic features in the source apk
    ori_callers = apk.sfcg_callers
    ori_apis= apk.sfcg_apis
    ori_calls = apk.calls

    # if basic_info is None:
    #     logging.info(red("Attack Self Crash ----- APK: {}".format(apk.name)))
    #     final_res_dir = os.path.join(output_result_dir, "self_crash", apk.name.split('.')[0])
    #     os.makedirs(final_res_dir, exist_ok=True)
    #     return

    # copy the backup apk
    # 将被攻击的apk复制到tmp目录下
    tmp_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
    os.makedirs(tmp_dir, exist_ok=True)
    copy_apk_path = os.path.join(tmp_dir, os.path.basename(apk.location))
    shutil.copy(apk.location, copy_apk_path)

    count = 0
    # 修改崩溃标识符
    modification_crash = False
    success = False
    start_time = time.time()
    parse_dir = os.path.join(tmp_dir, "unpack")
    backup_parse_dir = os.path.join(tmp_dir, "backup_unpack")
    # 解压 APK
    extract_apk(copy_apk_path, parse_dir)

    if os.path.exists(backup_parse_dir):
        shutil.rmtree(backup_parse_dir)
    shutil.copytree(parse_dir,backup_parse_dir)

    total_change = 0
    for attempt_idx in range(query_budget):
        # 随机选择一个action
        # action = PerturbationSelector.get_action()
        action,res =perturbation_selector.select_random_action(apk.cluster,ori_apis,ori_callers,ori_calls)
        if action == None:
            logging.info(red("Action is None ----- APK: {}".format(apk.name)))
            out+="Action is None ----- APK: {}\n".format(apk.name)
            modification_crash = True
            break
        out+=res
        logging.info(green("Query {} selects action:{} ----- APK: {}".format(attempt_idx,f"{action.caller}->{action.callee}",apk.name)))
        out+="Query {} selects action:{} with weight:{} ----- APK: {}\n".format(attempt_idx,f"{action.caller}->{action.callee}",action.weight,apk.name)
        # execute the action
        # 将action插入原apk
        # res, backup_dir, process_dir = execute_action(action, tmp_dir, copy_apk_path, inject_activity_name,
        #                                               inject_receiver_name, inject_receiver_data)
        # 备份插入前的apk
        backup_dir = os.path.join(tmp_dir, "backup")
        # 插入后的apk
        process_dir = os.path.join(tmp_dir, "process")
        
        os.makedirs(backup_dir, exist_ok=True)
        os.makedirs(process_dir, exist_ok=True)
        if action.caller in ori_callers:
            logging.info(green("Query {} try to insert a invoke.".format(attempt_idx)))
            out+="Query {} try to insert a invoke.\n".format(attempt_idx)
            res = insert_invoke(action,parse_dir, copy_apk_path,backup_dir,process_dir)
        else:           
            api = random.choice(ori_callers)                                              
            # res = insert_method(api,action,parse_dir, copy_apk_path,backup_dir,process_dir)
            logging.info(green("Query {} try to insert a smali.".format(attempt_idx)))
            out+="Query {} try to insert a smali, with the help of {}.\n".format(attempt_idx,api)
            res = insert_smali(api,action,parse_dir, copy_apk_path,backup_dir,process_dir)

        if not res:
            shutil.rmtree(parse_dir)
            shutil.copytree(backup_parse_dir,parse_dir)
            modification_crash = True
            break
        # 将插入后的apk复制到copy_apk_path
        os.remove(copy_apk_path)
        shutil.copy(os.path.join(process_dir, apk.name), copy_apk_path)

        # re-extract the feature of the new apk
        # 重新提取新构建的新apk的特征
        victim_feature = None
        if model.feature == "drebin":
            victim_feature = get_drebin_feature(copy_apk_path)
            victim_feature = model.vec.transform(victim_feature)
        elif model.feature == "apigraph":
            victim_feature = get_apigrah_feature(copy_apk_path)
            victim_feature = model.vec.transform(victim_feature)
        elif model.feature == "mamadroid":
            victim_feature = np.expand_dims(get_mamadroid_feature(copy_apk_path), axis=0)
        elif model.feature == "vae_fd":
            victim_feature = get_vae_fd_feature(copy_apk_path)
        assert victim_feature is not None

        # query the model
        # 使用新的特征访问model，得到confidence
        next_confidence = None
        if model.classifier == "svm":
            next_confidence = model.clf.decision_function(victim_feature)
        elif model.classifier == "mlp":
            next_confidence = model.clf.predict_proba(victim_feature)[0][1]
        elif model.classifier == "rf":
            next_confidence = model.clf.predict_proba(victim_feature)[0][1]
        elif model.classifier == "3nn":
            next_confidence = model.clf.predict_proba(victim_feature)[0][1]
        elif model.classifier == "fd_vae_mlp":
            next_confidence = model.clf.predict_proba(victim_feature)[0][1]
        assert next_confidence is not None

        # 得到新特征对应的类别，如果是0，即良性，则攻击成功，退出此次攻击
        next_label = model.clf.predict(victim_feature)
        if next_label == 0:
            success = True
            total_change += 1
            out += f"Action is positive:{action.caller}--->{action.callee}\n"
            out += "Query {} next confidence: {} ----- APK: {}\n".format(attempt_idx,next_confidence,apk.name)
            logging.info(green("Query {} next confidence: {} ----- APK: {}".format(attempt_idx,next_confidence,apk.name)))
            break
        else:
            logging.info(green("Query {} next confidence: {} ----- APK: {}".format(attempt_idx,next_confidence,apk.name)))
            out += "Query {} next confidence: {} ----- APK: {}\n".format(attempt_idx,next_confidence,apk.name)
            # logger.critical(green("Query {} next confidence: {} ----- APK: {}".format(attempt_idx,next_confidence,apk.name)))

        # perturbation_results : 1 represents positive effects, 0 represents no effects. -1 represents negative effects
        # 如果攻击后的置信度小于攻击前的置信度，那么这个扰动有效
        perturbation_results = next_confidence- prev_confidence
        if next_confidence < prev_confidence - 1e-4:
            ori_calls.append(f"{action.caller}--->{action.callee}")
            weight_bef = action.weight
            perturbation_selector.update_candidate_call_pro(apk.cluster,action, perturbation_results)
            if next_confidence < prev_confidence - 1e-1:
                logger.critical(green(" action in cluster {}: {} with weight: {} decrease confidence {}, weight after update: {}".format(action.cluster,f"{action.caller}->{action.callee}",weight_bef,next_confidence- prev_confidence,action.weight)))
            prev_confidence = next_confidence
            # 将插入后的反编译目录进行备份
            shutil.rmtree(backup_parse_dir)
            shutil.copytree(parse_dir,backup_parse_dir)
            # shutil.rmtree(parse_dir)
            shutil.rmtree(backup_dir)
            shutil.rmtree(process_dir)
            total_change += 1
            out += f"Action is positive:{action.caller}--->{action.callee}\n"
            out += "Query {} next confidence: {} ----- APK: {}\n".format(attempt_idx,next_confidence,apk.name)
        elif next_confidence > prev_confidence + 1e-4:
            # backtrace the apk
            shutil.copy(os.path.join(backup_dir, apk.name), copy_apk_path)
            shutil.rmtree(parse_dir)
            shutil.copytree(backup_parse_dir,parse_dir)
            perturbation_selector.update_candidate_call_pro(apk.cluster,action, perturbation_results)
            shutil.rmtree(backup_dir)
            shutil.rmtree(process_dir)
        else:
            perturbation_results = 0
            shutil.copy(os.path.join(backup_dir, apk.name), copy_apk_path)
            shutil.rmtree(parse_dir)
            shutil.copytree(backup_parse_dir,parse_dir)
            perturbation_selector.update_candidate_call_pro(apk.cluster,action, perturbation_results)
            shutil.rmtree(backup_dir)
            shutil.rmtree(process_dir)

    # 重置已选择
    perturbation_selector.reset_selected()
    print(perturbation_selector.selected_nodes)
    end_time = time.time()
    if success:
        logging.info(green("Attack Success ----- APK: {}".format(apk.name)))
        out+="Attack Success ----- APK: {}\n".format(apk.name)
        # logger.critical(green("Attack Success ----- APK: {}".format(apk.name)))
        final_res_dir = os.path.join(output_result_dir, "success", apk.name.split('.')[0])
        os.makedirs(final_res_dir, exist_ok=True)
        with open(os.path.join(final_res_dir, "efficiency.txt"), "w") as f:
            f.write(str(attempt_idx + 1) + "\n")
            f.write(str(end_time - start_time)+" seconds\n")
            f.write(str(total_change)+" changes\n")
        with open(os.path.join(final_res_dir, f"{apk.name.replace('.apk','.txt')}"), "w") as f:
            f.write(out)
        if os.path.exists(copy_apk_path):
            shutil.copy(apk.location, os.path.join(final_res_dir, apk.name.split('.')[0] + ".source"))
            shutil.copy(copy_apk_path, os.path.join(final_res_dir, apk.name.split('.')[0] + ".adv"))
    else:
        if modification_crash:
            logging.info(red("Attack Modification Crash ----- APK: {}".format(apk.name)))
            out+="Attack Modification Crash ----- APK: {}".format(apk.name)
            # logger.critical(red("Attack Modification Crash ----- APK: {}".format(apk.name)))
            final_res_dir = os.path.join(output_result_dir, "modification_crash", apk.name.split('.')[0])
            os.makedirs(final_res_dir, exist_ok=True)
            with open(os.path.join(final_res_dir, f"{apk.name.replace('.apk','.txt')}"), "w") as f:
                f.write(out)
        else:
            logging.info(red("Attack Fail ----- APK: {}".format(apk.name)))
            out+="Attack Fail ----- APK: {}".format(apk.name)
            # logger.critical(red("Attack Fail ----- APK: {}".format(apk.name)))
            final_res_dir = os.path.join(output_result_dir, "fail", apk.name.split('.')[0])
            os.makedirs(final_res_dir, exist_ok=True)
            with open(os.path.join(final_res_dir, f"{apk.name.replace('.apk','.txt')}"), "w") as f:
                f.write(out)

    shutil.rmtree(tmp_dir)
