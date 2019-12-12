import tensorflow as tf
import numpy as np
import csv
import os
import sys
import time
import networkx as nv
import itertools
from tqdm import tqdm
import core.config as config
from core.config import logging
from core.tfrecord_core import load_dataset, generate_cfg_dfg_pair
from core.tfrecord_core import generate_feature_pair
from core.tools import test_and_create_dirs


def construct_learning_dataset_i2v_funcsim(pair_list):
    cfgs_1, cfgs_2, dfgs_1, dfgs_2 = generate_cfg_dfg_pair(pair_list)
    feas_1, feas_2, max_size, nums_1, nums_2 = \
                                        generate_feature_pair(pair_list, 2)
    return cfgs_1, cfgs_2, dfgs_1, dfgs_2, feas_1, feas_2, nums_1, nums_2, max_size


def gen_tfrecord_and_save_i2v_funcsim(save_file, pair_list, label_list):
    cfgs_1, cfgs_2, dfgs_1, dfgs_2, feas_1, feas_2, nums_1, nums_2, max_size = \
                                construct_learning_dataset_i2v_funcsim(pair_list)
    node_list = np.linspace(max_size, max_size, len(label_list), dtype=int)
    writer = tf.python_io.TFRecordWriter(save_file)
    logging.info('generate tfrecord and save to {}'.format(save_file))
    for item1, item2, item3, item4, item5, item6, item7, item8, item9, item10 \
            in tqdm(zip(label_list, cfgs_1, cfgs_2, dfgs_1, dfgs_2, feas_1, \
                        feas_2, nums_1, nums_2, node_list)):
        feature = {
            'label': tf.train.Feature(int64_list = tf.train.Int64List(value=[item1])),
            'cfg_1': tf.train.Feature(bytes_list = tf.train.BytesList(value=[item2])),
            'cfg_2': tf.train.Feature(bytes_list = tf.train.BytesList(value=[item3])),
            'dfg_1': tf.train.Feature(bytes_list = tf.train.BytesList(value=[item4])),
            'dfg_2': tf.train.Feature(bytes_list = tf.train.BytesList(value=[item5])),
            'fea_1': tf.train.Feature(bytes_list = tf.train.BytesList(value=[item6])),
            'fea_2': tf.train.Feature(bytes_list = tf.train.BytesList(value=[item7])),
            'num_1': tf.train.Feature(int64_list = tf.train.Int64List(value=[item8])),
            'num_2': tf.train.Feature(int64_list = tf.train.Int64List(value=[item9])),
            'max': tf.train.Feature(int64_list = tf.train.Int64List(value=[item10])),
        }
        features = tf.train.Features(feature = feature)
        example_proto = tf.train.Example(features = features)
        serialized = example_proto.SerializeToString()
        writer.write(serialized)
    writer.close()

test_and_create_dirs(config.TFRECORD_TRAIN, \
                        config.TFRECORD_VALID, \
                        config.TFRECORD_TEST)

train_pair, train_label, valid_pair, valid_label, test_pair, test_label = load_dataset()
logging.info('generate tfrecord: i2v_funcsim train...')
gen_tfrecord_and_save_i2v_funcsim(config.TFRECORD_TRAIN, train_pair, train_label)
logging.info('generate tfrecord: i2v_funcsim valid...')
gen_tfrecord_and_save_i2v_funcsim(config.TFRECORD_VALID, valid_pair, valid_label)
logging.info('generate tfrecord: i2v_funcsim test...')
gen_tfrecord_and_save_i2v_funcsim(config.TFRECORD_TEST, test_pair, test_label)

