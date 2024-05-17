import os
import logging
import re
import numpy as np
import traceback
from androguard.misc import AnalyzeAPK
from settings import config
from utils import red, green

INTENT_ACTION_PATTERN = re.compile('action\s+android:name=\"(?P<action>.+)\"')


def get_vae_fd_feature(apk_path, output_path=None):
    total_feature = []
    try:
        a, d, dx = AnalyzeAPK(apk_path)

        # get the permission
        total_permissions = []
        with open(config['vae_permissions'], "r") as f:
            for line in f:
                total_permissions.append(line.strip())
        apk_permissions = set()
        for permission in a.get_permissions():
            apk_permissions.add(permission.split(".")[-1])
        for permission in total_permissions:
            if permission in apk_permissions:
                total_feature.append(1)
            else:
                total_feature.append(0)

        # get the action feature
        total_actions = []
        with open(config['vae_actions'], "r") as f:
            for line in f:
                total_actions.append(line.strip())
        android_manifest = a.get_android_manifest_axml().get_xml().decode()
        # for node in a.get_android_manifest_xml().findall(".//action"):
        #     print(node.attrib)
        apk_actions = set()
        for match in INTENT_ACTION_PATTERN.finditer(android_manifest):
            apk_actions.add(match.group('action').split('.')[-1])
        for action in total_actions:
            if action in apk_actions:
                total_feature.append(1)
            else:
                total_feature.append(0)

        # get the api feature
        total_apis = []
        with open(config['vae_apis'], "r") as f:
            for line in f:
                total_apis.append(line.strip())
        apk_methods = set()
        methods = dx.find_methods('.*', '.*', '.*', '.*')
        for method in methods:
            API = method.get_method()
            class_name = API.get_class_name()
            method_name = API.get_name()
            method_psedo_signature = class_name + "->" + method_name
            apk_methods.add(method_psedo_signature)
        for api in total_apis:
            if api in apk_methods:
                total_feature.append(1)
            else:
                total_feature.append(0)
    except:
        logging.error(red("Error occurred in APK: {}".format(os.path.basename(apk_path))))
        traceback.print_exc()

    if len(total_feature) < 147 + 126 + 106:
        total_feature = [0 for _ in range(147 + 126 + 106)]

    total_feature = np.array(total_feature, dtype=np.int)
    if output_path is not None:
        np.savez(output_path, vae_fd_feature=total_feature)
        logging.critical(green('Successfully save the vae-fd feature in: {}'.format(output_path)))
    return total_feature
