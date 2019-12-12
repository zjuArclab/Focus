import os
import sys
import logging

sys.path.append(os.path.dirname(__file__))

logging.basicConfig(stream = sys.stdout, \
                    # filename='logs/gen_train_dataset.log', \
                    #level=logging.DEBUG)
                    level=logging.INFO)


#PROGRAMS = ['openssl','busybox']
PROGRAMS = ['openssl']

ARCHS = ['all']

OPT_LEVELS = ['all'] # ['o0', 'o1', 'o2', 'o3']

TRAIN_DATASET_NUM = 100000

WORD2VEC_EMBEDDING_SIZE = 50
NUM_EPOCH = 5

# DATA ROOT
#DATA_ROOT_DIR = '/home/binary_similarity/data'
DATA_ROOT_DIR = '/home1/Project/binary_similarity/data'

# FEATURE
FEA_DIR = os.path.join(DATA_ROOT_DIR, 'features')
CFG_DFG = 'cfg_dfg_geminifea_vulseekerfea'


# DATASET
DATASET_MIN_BLOCK_NUM = 5
DATASET_MAX_BLOCK_NUM = 30

FILENAME_PREFIX = str(TRAIN_DATASET_NUM) + '_[' + \
                str(DATASET_MIN_BLOCK_NUM) + '_' + \
                str(DATASET_MAX_BLOCK_NUM) + ']_[' + \
                str(CFG_DFG) + ']_[' + \
                '_'.join(PROGRAMS) + ']_[' + \
                '_'.join(ARCHS) + ']_[' + \
                '_'.join(OPT_LEVELS) + ']'

DATASET_DIR = os.path.join(DATA_ROOT_DIR, 'datasets')
DATASET_TRAIN = os.path.join(DATASET_DIR, 'train' + FILENAME_PREFIX + '.csv')
DATASET_VALID = os.path.join(DATASET_DIR, 'valid' + FILENAME_PREFIX + '.csv')
DATASET_TEST = os.path.join(DATASET_DIR, 'test' + FILENAME_PREFIX + '.csv')

TFRECORD_DIR = os.path.join(DATA_ROOT_DIR, 'tfrecords')

TFRECORD_TRAIN = os.path.join(TFRECORD_DIR, \
                                'train' + FILENAME_PREFIX + '.tfrecord')
TFRECORD_VALID = os.path.join(TFRECORD_DIR, \
                                'valid' + FILENAME_PREFIX + '.tfrecord')
TFRECORD_TEST = os.path.join(TFRECORD_DIR, \
                                'test' + FILENAME_PREFIX + '.tfrecord')

# MODEL
MODEL_DIR = os.path.join(DATA_ROOT_DIR, 'models')


# STATIS
STATIS_DIR = os.path.join(DATA_ROOT_DIR, 'statis')

def config_test_and_create_dirs(*args):
    for fname in args:
        d = fname
        if os.path.isfile(fname):
            d, f = os.path.split(fname)
        if not os.path.exists(d):
            os.makedirs(d)

config_test_and_create_dirs( \
        DATA_ROOT_DIR, \
        CFG_DFG, \
        DATASET_DIR, \
        TFRECORD_DIR, \
        MODEL_DIR, \
        STATIS_DIR, \
    )
