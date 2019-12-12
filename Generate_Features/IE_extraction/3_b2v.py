#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import os
import time
import numpy as np
import gensim
import config
import idaapi
import idautils
import idc

idaapi.autoWait()

bin_num = 0
func_num = 0
function_list_file = ""
function_list_fp = None
functions = []
curBinNum = 0
#i2v_model = gensim.models.Word2Vec.load(config.SAVE_WORD2VEC_MODEL)
i2v_model = gensim.models.Word2Vec.load('D:\\Binary_Similarity\\norm_func1\\coreutils-8.29_findutils-4.6.0]_[all]_[all]_i2v_.model')
OOV_path =config.OOV_path

def op_count(ea):
    '''Return the number of operands of given instruction'''
    length = idaapi.decode_insn(ea)
    c = 0
    for c,v in enumerate(idaapi.cmd.Operands):
        if v.type == idaapi.o_void:
            return c
        continue
    # maximum operand count. ida might be wrong here...
    return c
def norm_func0(head):
    inst = '' + idc.GetMnem(head)
    num_operands = op_count(head)
    for i in range(num_operands):
        inst += ' ' + idc.GetOpnd(head, i)
        if num_operands > 1:
            inst += ','
    if ',' in inst:
        inst = inst[:-1]
    inst = inst.replace(' ', '_')
    return str(inst)

def norm_func3(head):
    inst = '' + idc.GetMnem(head)
    num_operands = op_count(head)
    for i in range(num_operands):
        inst += ' op' + str(i)
        if num_operands > 1:
            inst += ','
    if ',' in inst:
        inst = inst[:-1]
    inst = inst.replace(' ', '_')
    return str(inst)

# normalization method from SFAE
def norm_func1(head):

    inst = '' + idc.GetMnem(head)
    num_operands = op_count(head)
    for i in range(num_operands):
        type_op = idc.GetOpType(head, i)
        if type_op == idc.o_void:
            break
        elif type_op == idc.o_mem:
            inst += ' [MEM]'
        elif type_op == idc.o_imm:
            val = idc.GetOperandValue(head, i)
            #if -int(50000) <= val <= int(50000):
            #if -int(500) <= val <= int(500):
            if -int(100000) <= val <= int(100000):
                inst += ' ' + str(hex(val))
            else:
                inst += ' HIMM'
        else:
            inst += ' ' + idc.GetOpnd(head, i)

        if num_operands > 1:
            inst += ','

    if ',' in inst:
        inst = inst[:-1]
    inst = inst.replace(' ', '_')
    return str(inst)

def norm_func2(head):
    inst = '' + idc.GetMnem(head)
    num_operands = op_count(head)
    for i in range(num_operands):
        type_op = idc.GetOpType(head, i)
        if type_op == idc.o_void:
            inst += ' 0'
        elif type_op == idc.o_reg:
            inst += ' 1'
        elif type_op == idc.o_mem:
            inst += ' 2'
        elif type_op == idc.o_phrase:
            inst += ' 3'
        elif type_op == idc.o_displ:
            inst += ' 4'
        elif type_op == idc.o_imm:
            inst += ' 5'
        elif type_op == idc.o_far:
            inst += ' 6'
        elif type_op == idc.o_near:
            inst += ' 7'
        elif type_op == idc.o_idpspec0:
            inst += ' 8'
        elif type_op == idc.o_idpspec1:
            inst += ' 9'
        elif type_op == idc.o_idpspec2:
            inst += ' 10'
        elif type_op == idc.o_idpspec3:
            inst += ' 11'
        elif type_op == idc.o_idpspec4:
            inst += ' 12'
        elif type_op == idc.o_idpspec5:
            inst += ' 13'
        else:
            inst += ' ' + idc.GetOpnd(head, i)
        if num_operands > 1:
            inst += ','

    if ',' in inst:
        inst = inst[:-1]
    inst = inst.replace(' ', '_')
    return str(inst)

def calBasicBlockFeature_i2v(block):
    res = np.zeros(config.embedding_size)
    num_insts = 0
    curEA = block.startEA
    while curEA <= block.endEA:
        num_insts += 1
        norm_inst = eval(config.Normalize_type)(curEA)
        if norm_inst not in i2v_model:
            with open(OOV_path, 'a') as f:
                f.write(norm_inst + '\n')
        else:
            res += i2v_model.wv[norm_inst]  ####################################basic block embedding = the sum of all instruction embedding
        curEA = idc.NextHead(curEA, block.endEA)

    fea_str = ','.join([str(i) for i in res])
    fea_str += ','
    return fea_str


def i2v_block_fea(allblock, fea_fp):
    for block in allblock:
        fea_str = calBasicBlockFeature_i2v(block)
        fea_str = str(hex(block.startEA)) + "," + fea_str + "\n"
        fea_fp.write(fea_str)


def main():
    global bin_num, func_num, function_list_file, function_list_fp, functions
    if len(idc.ARGV) < 1:
        sys.exit(0)
    else:
        fea_path_origion = idc.ARGV[1] #J:\flr\Project\Binary_similarity\B2V\cross_platform\norm_func2\b2v\busybox\busybox-1.27.0_aarch64_o0
        fea_path_temp = idc.ARGV[1] + "\\temp" #J:\flr\Project\Binary_similarity\B2V\cross_platform\norm_func2\b2v\busybox\busybox-1.27.0_aarch64_o0\temp
        bin_path = idc.ARGV[2]  #G:\VulSeeker\VulSeeker\0_Libs\busybox\busybox-1.27.0_aarch64_o0\busybox.i64
        binary_file = bin_path.split(os.sep)[-1]
        program = idc.ARGV[3]  #busybox
        version = idc.ARGV[4]  #busybox-1.27.0_aarch64_o0

    fname_prefix = '_'.join(binary_file.split('.')[:-1])

    # print "Directory path	：	", fea_path_origion
    function_list_file = fea_path_origion + os.sep + "functions_list_fea.csv"
    function_list_fp = open(function_list_file, 'a')  # a 追加

    textStartEA = 0
    textEndEA = 0
    for seg in idautils.Segments():
        if (idc.SegName(seg) == ".text"):
            textStartEA = idc.SegStart(seg)
            textEndEA = idc.SegEnd(seg)
            break
    for func in idautils.Functions(textStartEA, textEndEA):
        # Ignore Library Code
        flags = idc.GetFunctionFlags(func)
        if flags & idc.FUNC_LIB:
            # print hex(func), "FUNC_LIB", idc.GetFunctionName(func)
            continue
        cur_function_name = fname_prefix + '_' + idc.GetFunctionName(func)
        print cur_function_name
        fea_path = fea_path_origion
        if cur_function_name.lower() in functions:
            fea_path = fea_path_temp # repeat function occur
            if not os.path.exists(fea_path):
                os.mkdir(fea_path)
        functions.append(cur_function_name.lower())
        allblock = idaapi.FlowChart(idaapi.get_func(func))

        # if str(cur_function_name) == "libcrypto_so_1_0_CAST_decrypt":
        #     fp = open('I:\\b2v\\xxx.txt', 'w')
        #     for block in allblock:
        #         fp.write(str(hex(block.startEA)) + "\n")
        #     fp.close()

        fea_file = fea_path + os.sep + str(cur_function_name) + "_fea.csv"
        fea_fp = open(fea_file, 'w')
        i2v_block_fea(allblock, fea_fp)
        fea_fp.close()
        function_str = str(cur_function_name) + "," + \
                       str(program) + "," + str(version) + "," + str(bin_path) + ",\n"
        function_list_fp.write(function_str)
    function_list_fp.close()
    return
#

# def stdout_to_file(output_file_name, output_dir=None):
#     if not output_dir:
#         output_dir = os.path.dirname(os.path.realpath(__file__))
#     output_file_path = os.path.join(output_dir, output_file_name)
#     print output_file_path
#     print "original output start"
#     # save original stdout descriptor
#     orig_stdout = sys.stdout
#     # create output file
#     f = file(output_file_path, "w")
#     # set stdout to output file descriptor
#     sys.stdout = f
#     return f, orig_stdout

if __name__ == '__main__':
    # f, orig_stdout = stdout_to_file("output_" + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())) + ".txt")
    main()
    # print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    # sys.stdout = orig_stdout  # recover the output to the console window
    # f.close()

    idc.Exit(0)
