import pickle
import ujson as json
from models.drebin import get_drebin_feature
from settings import config

def transfer_apigraph_feature(drebin_feture, api_cluster_dict):
    apicall_name = drebin_feture.split("::")[1]
    if ";->" in apicall_name:
        method_name = apicall_name.split(";->")[1]
        class_name = apicall_name.split(";->")[0].replace("/", ".")
        drebin_api_name = class_name + "." + method_name
        if api_cluster_dict.get(drebin_api_name) is not None:
            return "apigraph::cluster-{}".format(api_cluster_dict[drebin_api_name])
        else:
            return None
    else:
        drebin_api_name = apicall_name.replace("/", ".") + "."
        for key in api_cluster_dict:
            if key.startswith(drebin_api_name):
                return "apigraph::cluster-{}".format(api_cluster_dict[key])


def get_apigrah_feature(apk_path, output_path=None):
    apigraph_clustering_feature_fn = config['clustering_info']
    with open(apigraph_clustering_feature_fn, "rb") as f:
        apigraph_clustering_feature = pickle.load(f)
    drebin_feature = get_drebin_feature(apk_path)
    apigraph_feature = dict()
    for key in drebin_feature:
        if key.startswith("api_calls"):
            apigraph_feature_value = transfer_apigraph_feature(key, apigraph_clustering_feature)
            if apigraph_feature_value is not None:
                apigraph_feature[apigraph_feature_value] = 1
        else:
            apigraph_feature[key] = 1
    if output_path is not None:
        with open(output_path, "w") as f:
            json.dump(apigraph_feature, f)
    return apigraph_feature
