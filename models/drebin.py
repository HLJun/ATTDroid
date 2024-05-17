import glob
import shutil
from settings import config
import tempfile
import logging
from utils import blue
import subprocess
import ujson as json

# 提取apk的drebin特征
def get_drebin_feature(apk_path, output_path=None):
    # 创建临时目录
    output_dir = tempfile.mkdtemp(dir=config['tmp_dir'])
    cmd = ['python3', './drebin.py', apk_path, output_dir]
    location = config['drebin_feature_extractor']
    logging.info(blue('Running command') + f' @ \'{location}\': {" ".join(cmd)}')
    subprocess.call(cmd, cwd=location)
    results_file = glob.glob(output_dir + '/results/*.json')[0]
    logging.debug('Extractor results in: {}'.format(results_file))
    with open(results_file, 'rt') as f:
        results = json.load(f)
    shutil.rmtree(output_dir)
    results.pop('sha256')  # Ensure hash isn't included in features

    if output_path is not None:
        with open(output_path, "w") as f:
            json.dump(results, f)

    return results
