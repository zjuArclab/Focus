import csv
import os
import sys
import glob
import pdb
import random
from tqdm import tqdm
from collections import defaultdict
import core.config as config
from core.config import logging
from core.tools import filter_by_arch_opt_levels

block_num_min = config.DATASET_MIN_BLOCK_NUM
block_num_max = config.DATASET_MAX_BLOCK_NUM 

pos_num = 1
neg_num = 1

train_dataset_num = config.TRAIN_DATASET_NUM
valid_dataset_num = int(train_dataset_num / 10)
test_dataset_num = int(train_dataset_num / 10)

# pdb.set_trace()

index_uuid = dict()
index_count = 0
for program in config.PROGRAMS:
    dirs = os.listdir(os.path.join(config.FEA_DIR, program, \
                        config.CFG_DFG))

    logging.debug('original dirs:{}\n{}'.format(dirs, len(dirs)))

    dirs = [d for d in dirs if filter_by_arch_opt_levels(d)]

    logging.debug('PROGRAMS: {}, ARCHS: {}, OPT_LEVELS: {}'.format( \
                    config.PROGRAMS, config.ARCHS, config.OPT_LEVELS))
    logging.debug('filtered dirs:{}\n{}'.format(dirs, len(dirs)))
    for d in dirs:
        index_uuid.setdefault(str(index_count), os.path.join(program, d))
        index_count += 1
        print(d)
    logging.debug('index_uuid: {}'.format(index_uuid))
    logging.debug('index_count: {}'.format(index_count))

func_list_arr = []
func_list_dict = defaultdict(list)

for k, v in index_uuid.items():
    program, v = v.split(os.sep)
    cur_functions_list_file = os.path.join(config.FEA_DIR, program, \
                config.CFG_DFG, v, 'functions_list.csv')
    if not os.path.exists(cur_functions_list_file):
        logging.error('No functions_list.csv in {}'.format(v))
    with open(cur_functions_list_file, 'r') as fp:
        logging.debug('Gen dataset: {}'.format(cur_functions_list_file))
        for line in csv.reader(fp):
            if line[0] == '':
                continue
            if block_num_max > 0:
                if not (int(line[1]) >= block_num_min and \
                            int(line[1]) <= block_num_max):
                    continue
            if line[0] not in func_list_dict:
                func_list_arr.append(line[0])
            value = os.path.join(line[4], \
                    config.CFG_DFG, line[5], line[0])
            func_list_dict[line[0]].append(value)

logging.debug('len(func_list_arr): {}'.format(len(func_list_arr)))

random.shuffle(func_list_arr)

func_list_train = []
func_list_valid = []
func_list_test = []

for i in range(len(func_list_arr)):
    if i % 12 == 0:
        func_list_test.append(func_list_arr[i])
    elif i % 12 == 1:
        func_list_valid.append(func_list_arr[i])
    else:
        func_list_train.append(func_list_arr[i])

logging.debug('len(func_list_train(): {}'.format(len(func_list_train)))
logging.debug('len(func_list_valid(): {}'.format(len(func_list_valid)))
logging.debug('len(func_list_test(): {}'.format(len(func_list_test)))

def gen_dataset_and_save(func_list_dict, func_list, save_file, dataset_num, \
                            pos_num=1, neg_num=1):
    cur_num = 0
    with open(save_file, 'w') as fp:
        for count in tqdm(range(dataset_num)):
            if cur_num < pos_num:
                random_func = random.sample(func_list, 1)
                select_list = func_list_dict[random_func[0]]
                while len(select_list) <= 1:
                    random_func = random.sample(func_list, 1)
                    select_list = func_list_dict[random_func[0]]
                selected_list = random.sample(select_list, 2)
                fp.write(selected_list[0] + ',' + selected_list[1] + ',1\n')
            elif cur_num < pos_num + neg_num:
                random_func = random.sample(func_list, 2)
                select_list1 = func_list_dict[random_func[0]]
                select_list2 = func_list_dict[random_func[1]]
                selected_list1 = random.sample(select_list1, 1)
                selected_list2 = random.sample(select_list2, 1)
                fp.write(selected_list1[0] + ',' + selected_list2[0] + ',-1\n')
            cur_num += 1
            if cur_num == pos_num + neg_num:
                cur_num = 0

gen_dataset_and_save(func_list_dict, func_list_train, config.DATASET_TRAIN, \
            train_dataset_num, pos_num, neg_num)
gen_dataset_and_save(func_list_dict, func_list_valid, config.DATASET_VALID, \
            valid_dataset_num, pos_num, neg_num)
gen_dataset_and_save(func_list_dict, func_list_test, config.DATASET_TEST, \
            test_dataset_num, pos_num, neg_num)
