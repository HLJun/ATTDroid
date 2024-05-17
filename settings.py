import os

_project_path = '/home/hlj/code/android/code/ATTDroid/'


def _project(base):
    return os.path.join(_project_path, base)


config = {
    # Experiment settings
    'dataset':'cic20',
    'saved_models': _project('model_results/cic20/models'),
    'saved_features': _project('model_results/cic20/features'),
    'saved_jsons':_project('model_results/cic20/jsons'),
    'labels': _project('train_data/cic20/cic20-y.json'),
    'meta_data': _project('train_data/cic20/cic20-meta-old.json'),
    'dataset_data':_project('train_data/'),
    'parse_dir':'/home/hlj/dev/shm/gnip/tmp/unpack/',
    'android_sdk': '/home/hlj/tool/androidSdk/tools/bin/',
    'tmp_dir': '/home/hlj/dev/shm/gnip/tmp/',
    # 保存攻击结果的目录
    'results_dir': '/home/hlj/dev/shm/gnip/ATT/results/',
    # 数据集的源目录
    'source_apk_path': '/data1/CIC/2020/',
    # 保存FCG的目录
    'fcg_dirs': '/data/hlj/datas/cic20/fcg/',
    'sfcg_dirs': '/data/hlj/datas/cic20/sfcg/',
    # 保存数据集切片的目录
    'slice_database': '/home/hlj/dev/shm/gnip/ATT/slices_database/',
    'action_set': '/home/hlj/code/android/code/ATTDroid/model_results/cic20/jsons/',
    # 签名需要的工具
    "resigner": _project("java-components/apk-signer.jar"),

    # drebin
    'drebin_feature_extractor': _project('drebin-feature-extractor'),
    'drebin_api_path': _project('drebin-feature-extractor/APIcalls.txt'),

    # mamadroid
    'family_list': _project('meta_info/mamadroid/families.txt'),
    'package_list': _project('meta_info/mamadroid/packages.txt'),

    # apigraph
    "clustering_info": _project('meta_info/apigraph/method_cluster_mapping_2000.pkl'),

    # vae-fd
    "vae_permissions": _project("meta_info/vae/list_total_permissions.txt"),
    "vae_actions": _project("meta_info/vae/list_total_actions.txt"),
    "vae_apis": _project("meta_info/vae/list_total_apis.txt"),

    # Modifier
    "slicer": _project('java-components/slicer.jar'),
    "manifest": _project('java-components/manifest.jar'),
    "injector": _project('java-components/injector.jar'),

    # Misc
    'nproc_feature': 10,
    'nproc_slicer': 10,
    'nproc_attacker': 10,
    'sign': False,
    'extract_feature': False,  # Extract the feature
    'prepare_dataset':False,
    'serial': False,  # Attack in serial
}
