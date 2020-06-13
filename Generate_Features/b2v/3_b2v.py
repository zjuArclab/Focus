#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import os
import numpy as np
import gensim
import config
import csv
import argparse


bin_num = 0
func_num = 0
function_list_file = ""
function_list_fp = None
functions = []  # 由于windows文件名不区分大小写，这里记录已经分析的函数名（全部转换成小写，若重复，则添加当前时间戳作为后缀）

OOV_path = config.OOV_path
COUNT_path = config.COUNT_path

parser = argparse.ArgumentParser(description = 'Generate b2v.')

parser.add_argument('-fea_path', '--fea_path', \
            help = 'Path to store b2v featrue', \
            type = str, \
            required=True)
#parser.add_argument('-bin_path', '--bin_path', \
#            help = 'Path where binary file is stored', \
#            type = str, \
#            required=True)
parser.add_argument('-program', '--program', \
            help = 'Name of program', \
            type = str, \
            required=True)
parser.add_argument('-version', '--version', \
            help = 'Name of program version', \
            type = str, \
            required=True)

args = parser.parse_args()
fea_path = args.fea_path
#bin_path = args.bin_path
program = args.program
version = args.version

def main():
    global bin_num, func_num, function_list_file, function_list_fp, functions
    global fea_path, program, version
    fea_path_origion = fea_path
    fea_path_temp = fea_path + "\\temp"

    # 已经生成过的函数List
    known_function_list_file = config.FEA_DIR + os.sep + program + os.sep + version + os.sep + "functions_list_fea.csv"
    print known_function_list_file
    function_list_file = fea_path_origion + os.sep + "functions_list_fea.csv"
    function_list_fp = open(function_list_file, 'a')  # a 追加

    known_fp = open(known_function_list_file,'r')
    function_reader = csv.reader(known_fp)
    
    i2v_model = gensim.models.Word2Vec.load(config.SAVE_WORD2VEC_MODEL)
    count = 0
    for line in function_reader:
        func = line[0]
        cur_function_name = func
        if cur_function_name.lower() in functions:
            fea_path = fea_path_temp # repeat function occur
            if not os.path.exists(fea_path):
                os.mkdir(fea_path)
        functions.append(cur_function_name.lower())
        
        norm_file_name = 'function_norm_inst' + os.sep + cur_function_name + '_norm.csv'
        norm_file_name = config.Normalize_INST_DIR + os.sep + config.Normalize_type + os.sep + program + os.sep + version + os.sep + norm_file_name
        fea_file = fea_path + os.sep + str(cur_function_name) + "_fea.csv"
        try:
            fea_fp = open(fea_file, 'w')
            norm_fp = open(norm_file_name,'r')
            function_inst_count = 0
            function_oov_count=0
            for norm_line in norm_fp.readlines():
                norm_line = norm_line.strip('\n')       # 需要去掉换行符
                norm_lines = norm_line.split('\t')
                startEA = norm_lines[0]
                res = np.zeros(50)
                function_inst_count+=len(norm_lines)-1
                for i in range(1,len(norm_lines)):
                    norm_inst=norm_lines[i]
                    if norm_inst not in i2v_model:
                        function_oov_count+=1
                        with open(OOV_path, 'a') as f:
                            f.write(cur_function_name + ',' + norm_inst + '\n')
                    else:
                    	res += i2v_model.wv[norm_inst]
                fea_str = ','.join([str(i) for i in res])
                fea_str += ','
                fea_str = startEA + ',' + fea_str + '\n'
                fea_fp.write(fea_str)
            norm_fp.close()
            fea_fp.close()
            #function_str = str(cur_function_name) + "," + \
            #              str(program) + "," + str(version) + "," + str(bin_path) + ",\n"
            function_str = str(cur_function_name) + "," + \
                           str(program) + "," + str(version) + ",\n"
            function_list_fp.write(function_str)
            function_count_str = str(cur_function_name) + "," + str(function_inst_count) + "," + str(function_oov_count) + ",\n"
            with open(COUNT_path,'a') as f:
                f.write(function_count_str)
        except:
            print cur_function_name
        count += 1
        if count % 1000 == 0:
            print count
    function_list_fp.close()
    known_fp.close()
    return

if __name__ == '__main__':
    main()
