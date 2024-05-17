import os
import sys
import logging
import subprocess
from settings import config
from termcolor import colored
import sklearn
import numpy as np

red = lambda x: colored(x, 'red')
green = lambda x: colored(x, 'green')
yellow = lambda x: colored(x, 'yellow')
blue = lambda x: colored(x, 'blue')
magenta = lambda x: colored(x, 'magenta')
cyan = lambda x: colored(x, 'cyan')


def configure_logging(run_tag, debug=True):
    fmt = f'[ {run_tag} | %(asctime)s | %(name)s | %(processName)s | %(levelname)s ] %(message)s'
    datefmt = '%Y-%m-%d | %H:%M:%S'
    level = logging.DEBUG if debug else 100  # 100 == no logging
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)


def run_java_component(jar, args, cwd, timeout=None):
    """Wrapper for calling Java processes used for extraction and injection."""
    cmd = ['java', '-jar', jar, *args]
    logging.info(blue('Running command') + f': {" ".join(cmd)}')

    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.PIPE, timeout=timeout, cwd=cwd)
        out = str(out, 'utf-8')
        logging.debug(blue("The output of above java command: ") + green(out))
        return out
    except subprocess.TimeoutExpired:
        logging.warning(f'Java component {jar} timed out.')
    except subprocess.CalledProcessError as e:
        exception = "\nexit code :{0} \nSTDOUT :{1} \nSTDERROR : {2} ".format(
            e.returncode,
            e.output.decode(sys.getfilesystemencoding()),
            e.stderr.decode(sys.getfilesystemencoding()))
        logging.warning(
            f'SUBPROCESS Extraction EXCEPTION: {exception}')
    return ''


def sign_apk(apk_path):
    run_java_component(config['resigner'], ['--overwrite', '-a', apk_path], cwd=os.path.dirname(apk_path))


def calculate_base_metrics(model, y_pred, y_scores):
    """Calculate ROC, F1, Precision and Recall for given scores.

    Args:
        model: `Model` containing `y_test` of ground truth labels aligned with `y_pred` and `y_scores`.
        y_pred: Array of predicted labels, aligned with `y_scores` and `model.y_test`.
        y_scores: Array of predicted scores, aligned with `y_pred` and `model.y_test`.

    Returns:
        dict: Model performance stats.

    """
    if y_scores is None:
        roc = None
    else:
        if len(y_scores.shape) == 2:
            roc = sklearn.metrics.roc_auc_score(np.eye(2)[model.y_test], y_scores)
        else:
            roc = sklearn.metrics.roc_auc_score(model.y_test, y_scores)
    f1 = sklearn.metrics.f1_score(model.y_test, y_pred)
    precision = sklearn.metrics.precision_score(model.y_test, y_pred)
    recall = sklearn.metrics.recall_score(model.y_test, y_pred)

    return {
        'model_performance': {
            'roc': roc,
            'f1': f1,
            'precision': precision,
            'recall': recall,
        }
    }
