import os
import sys
import time 
import csv
import json
import pickle
from tqdm import tqdm
import tensorflow as tf
import numpy as np
from sklearn.metrics import roc_curve
from sklearn.metrics import auc
from collections import defaultdict

# sys.path.append('/home/simon/zpl/FuncSim')
# sys.path.append('/home/xiqian/Binary_similarity/FuncSim/FuncSim')
sys.path.append(os.path.dirname(__file__))

import config as config
from config import logging
from tools import filter_by_arch_opt_levels

block_num_min = config.DATASET_MIN_BLOCK_NUM
block_num_max = config.DATASET_MAX_BLOCK_NUM

def statis_save(save_file, content):
    head, tail = os.path.split(save_file)
    if not os.path.exists(head):
        os.makedirs(head)
    with open(save_file, 'wb') as f:
        pickle.dump(content, f)

def test_statis_load(load_file):
    with open(load_file, 'rb') as fp:
        contents = pickle.load(fp)
    print(type(contents))
    for k, v in contents.items():
        print(k)
        # print(v)

def get_num_block_statistics():
    index_uuid = dict()
    index_count = 0
    for program in config.PROGRAMS:
        dirs = os.listdir(os.path.join(config.FEA_DIR, program, \
                            config.CFG_DFG_GEMINIFEA_VULSEEKERFEA))
    
        logging.debug('original dirs:{}\n{}'.format(dirs, len(dirs)))
    
        dirs = [d for d in dirs if filter_by_arch_opt_levels(d)]
    
        logging.debug('PROGRAMS: {}, ARCHS: {}, OPT_LEVELS: {}'.format( \
                        config.PROGRAMS, config.ARCHS, config.OPT_LEVELS))
        logging.debug('filtered dirs:{}\n{}'.format(dirs, len(dirs)))
        for d in dirs:
            index_uuid.setdefault(str(index_count), os.path.join(program, d))
            index_count += 1
    
        logging.debug('index_uuid: {}'.format(index_uuid))
        logging.debug('index_count: {}'.format(index_count))


    func_list_arr = []
    func_list_dict = defaultdict(list)
    block_num_dict = defaultdict(int)
    
    for k, v in index_uuid.items():
        program, v = v.split(os.sep)
        cur_functions_list_file = os.path.join(config.FEA_DIR, program, \
                    config.CFG_DFG_GEMINIFEA_VULSEEKERFEA, v, 'functions_list.csv')
        if not os.path.exists(cur_functions_list_file):
            logging.error('No functions_list.csv in {}'.format(v))
        with open(cur_functions_list_file, 'r') as fp:
            logging.debug('Gen dataset: {}'.format(cur_functions_list_file))
            for line in csv.reader(fp):
                if line[0] == '':
                    continue
                block_num_dict[int(line[1])] += 1
                if block_num_max > 0:
                    if not (int(line[1]) >= block_num_min and \
                                int(line[1]) <= block_num_max):
                        continue
                if line[0] not in func_list_dict:
                    func_list_arr.append(line[0])
                value = os.path.join(line[4], \
                        config.CFG_DFG_GEMINIFEA_VULSEEKERFEA, line[5], line[0])
                func_list_dict[line[0]].append(value)
    return block_num_dict, len(func_list_arr)

block_num_dict, unique_func_num = get_num_block_statistics()
total_func_num = 0
temp = 0
for k in sorted(block_num_dict.keys()):
    temp += block_num_dict[k]
    if int(k) >= block_num_min and int(k) <= block_num_max:
        total_func_num += block_num_dict[k]
    print('{} : {}'.format(k, block_num_dict[k]))

# with open('total_block_distri_statis.json', 'w') as fp:
#     json.dump(block_num_dict, fp, indent = 4, sort_keys = True)

print('all total functions: {}'.format(temp))
print('block num boundary: [{}, {}]'.format(block_num_min, block_num_max))
print('\ttotal num functions: {}'.format(total_func_num))
print('\tunique num functions: {}'.format(unique_func_num))
