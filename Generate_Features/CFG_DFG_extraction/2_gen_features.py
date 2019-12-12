#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys
import errno
#sys.path.append("/home/xiqian/Binary_similarity/IDA/IDA_Pro_v6.4/python/lib/python2.7/site-packages")
import config
import config_for_feature
import networkx as nx
import idaapi
import idautils
import idc
import os
import time
import shutil
from utils import guess_machine, expr2colorstr
from miasm.core.bin_stream_ida import bin_stream_ida
from miasm.core.asmblock import expr_is_label, AsmLabel, is_int
from miasm.expression.simplifications import expr_simp
from miasm.analysis.data_flow import dead_simp
from miasm.ir.ir import AssignBlock, IRBlock

import re
import subprocess

idaapi.autoWait()

bin_num = 0
func_num = 0
function_list_file = ""
function_list_fp = None
functions = []
curBinNum = 0


class bbls:
    id = ""
    define = []
    use = []
    defuse = {}
    fathernode = set()
    childnode = set()
    define = set()
    use = set()
    visited = False


def calConstantNumber(ea):
    i = 0;
    curStrNum = 0
    numeric = 0
    # print idc.GetDisasm(ea)
    while i <= 1:
        if (idc.GetOpType(ea, i) == 5):
            addr = idc.GetOperandValue(ea, i)
            if (idc.SegName(addr) == '.rodata') and (idc.GetType(addr) == 'char[]') and (i == 1):
                curStrNum = curStrNum + 1
            else:
                numeric = numeric + 1
        i = i + 1
    return numeric, curStrNum;



def calBasicBlockFeature_vulseeker(block):
    StackNum = 0  # stackInstr
    MathNum = 0  # arithmeticInstr
    LogicNum = 0  # logicInstr
    CompareNum = 0  # compareInstr
    ExCallNum = 0  # externalInstr
    InCallNum = 0  # internalInstr
    ConJumpNum = 0  # conditionJumpInstr
    UnConJumpNum = 0  # unconditionJumpInstr
    GeneicNum = 0  # genericInstr
    curEA = block.startEA
    while curEA <= block.endEA:
        inst = idc.GetMnem(curEA)
        if inst in config_for_feature.VulSeeker_stackInstr:
            StackNum = StackNum + 1
        elif inst in config_for_feature.VulSeeker_arithmeticInstr:
            MathNum = MathNum + 1
        elif inst in config_for_feature.VulSeeker_logicInstr:
            LogicNum = LogicNum + 1
        elif inst in config_for_feature.VulSeeker_compareInstr:
            CompareNum = CompareNum + 1
        elif inst in config_for_feature.VulSeeker_externalInstr:
            ExCallNum = ExCallNum + 1
        elif inst in config_for_feature.VulSeeker_internalInstr:
            InCallNum = InCallNum + 1
        elif inst in config_for_feature.VulSeeker_conditionJumpInstr:
            ConJumpNum = ConJumpNum + 1
        elif inst in config_for_feature.VulSeeker_unconditionJumpInstr:
            UnConJumpNum = UnConJumpNum + 1
        else:
            GeneicNum = GeneicNum + 1

        curEA = idc.NextHead(curEA, block.endEA)

    fea_str = str(StackNum) + "," + str(MathNum) + "," + str(LogicNum) + "," + str(CompareNum) + "," \
              + str(ExCallNum) + "," + str(ConJumpNum) + "," + str(UnConJumpNum) + "," + str(GeneicNum) + ","
    return fea_str


def calBasicBlockFeature_gemini(block):
    numericNum = 0
    stringNum = 0
    transferNum = 0
    callNum = 0
    InstrNum = 0
    arithNum = 0
    logicNum = 0
    curEA = block.startEA
    while curEA <= block.endEA:
        numer, stri = calConstantNumber(curEA)
        numericNum = numericNum + numer
        stringNum = stringNum + stri
        if idc.GetMnem(curEA) in config_for_feature.Gemini_allTransferInstr:
            transferNum = transferNum + 1
        if idc.GetMnem(curEA) == 'call':
            callNum = callNum + 1
        InstrNum = InstrNum + 1
        if idc.GetMnem(curEA) in config_for_feature.Gemini_arithmeticInstr:
            arithNum = arithNum + 1
        if idc.GetMnem(curEA) in config_for_feature.Gemini_logicInstr:
            logicNum = logicNum + 1
        curEA = idc.NextHead(curEA, block.endEA)

    fea_str = str(numericNum) + "," + str(stringNum) + "," + str(transferNum) + "," + str(callNum) + "," + str(
        InstrNum) + "," + str(arithNum) + "," + str(logicNum) + ","
    return fea_str


def block_fea(allblock, fea_fp):
    for block in allblock:
        gemini_str = calBasicBlockFeature_gemini(block)
        vulseeker_str = calBasicBlockFeature_vulseeker(block)
        fea_str = str(hex(block.startEA)) + "," + gemini_str + vulseeker_str + "\n"
        fea_fp.write(fea_str)


def build_dfg(DG, IR_blocks):
    IR_blocks_dfg = IR_blocks
    startnode = ''
    linenum = 0
    for in_label, in_value in IR_blocks.items():
        linenum = 0
        addr = in_label.split(":")[1].strip()
        tempbbls = bbls()
        tempbbls.id = addr
        tempbbls.childnode = set()
        tempbbls.fathernode = set()
        tempbbls.defuse = {}
        tempbbls.defined = {}
        tempbbls.used = {}
        tempbbls.definedset = set()
        tempbbls.visited = False
        IR_blocks_dfg[addr] = tempbbls

        for i in in_value:
            linenum += 1
            if '=' not in i or "call" in i or 'IRDst' in i:
                continue

            define = i.split('=')[0].strip()
            if '[' in define:
                define = define[define.find('[') + 1:define.find(']')]
            use = i.split('=')[1].strip()
            if define not in tempbbls.defined:
                tempbbls.defined[define] = [linenum, 0]
            else:
                tempbbls.defined[define][1] = linenum

            if define not in IR_blocks_dfg[addr].defuse:
                IR_blocks_dfg[addr].defuse[define] = set()


            if '(' not in use and '[' not in use:
                IR_blocks_dfg[addr].defuse[define].add(use)
                if use not in tempbbls.used:
                    tempbbls.used[use] = [linenum, 0]
                else:
                    tempbbls.used[use][1] = linenum

            else:
                srclist = list(i)
                for i in range(len(srclist)):
                    if srclist[i] == ")" and srclist[i - 1] != ")":
                        tmp = srclist[0:i + 1][::-1]
                        for j in range(len(tmp)):
                            if tmp[j] == "(":
                                temps = "".join(srclist[i - j:i + 1])
                                if temps.count(')') == 1 and temps.count('(') == 1:
                                    temps = temps[1:-1]
                                    IR_blocks_dfg[addr].defuse[define].add(temps)
                                    if temps not in tempbbls.used:
                                        tempbbls.used[temps] = [linenum, 0]
                                    else:
                                        tempbbls.used[temps][1] = linenum

                                break

                for i in range(len(srclist)):
                    if srclist[i] == "]" and srclist[i - 1] != "]":
                        tmp = srclist[0:i + 1][::-1]
                        for j in range(len(tmp)):
                            if tmp[j] == "[":
                                temps = "".join(srclist[i - j:i + 1])
                                if temps.count(']') == 1 and temps.count(']') == 1:
                                    temps = temps[1:-1]
                                    IR_blocks_dfg[addr].defuse[define].add(temps)
                                    if temps not in tempbbls.used:
                                        tempbbls.used[temps] = [linenum, 0]
                                    else:
                                        tempbbls.used[temps][1] = linenum
                                break



    for cfgedge in DG.edges():
        innode = str(cfgedge[0])
        outnode = str(cfgedge[1])

        if innode == outnode:
            continue
        if IR_blocks_dfg.has_key(innode):
            IR_blocks_dfg[innode].childnode.add(outnode)
        if IR_blocks_dfg.has_key(outnode):
            IR_blocks_dfg[outnode].fathernode.add(innode)


    cfg_nodes = DG.nodes()
    startnode = None
    for addr, bbloks in IR_blocks_dfg.items():
        if ':' in addr:
            continue
        if len(cfg_nodes) == 1 or startnode is None:
            startnode = addr

        if addr in cfg_nodes and len(IR_blocks_dfg[addr].fathernode) == 0:
            startnode = addr
        for definevar in IR_blocks_dfg[addr].defuse:
            IR_blocks_dfg[addr].definedset.add(definevar)

    if startnode is None:
        return nx.DiGraph()
    else:
        return gen_dfg(IR_blocks_dfg, startnode)


def gen_dfg(IR_blocks_dfg, startnode):

    res_graph = nx.DiGraph()

    stack_list = []
    visited = {}

    visited2 = {}

    visited3 = {}
    for key, val in IR_blocks_dfg.items():
        visited2[key] = set()
        visited3[key] = set()
    visitorder = []

    IR_blocks_dfg[startnode].visited = True
    visited[startnode] = '1'
    visitorder.append(startnode)
    stack_list.append(startnode)
    while len(stack_list) > 0:
        cur_node = stack_list[-1]
        next_nodes = set()
        if IR_blocks_dfg.has_key(cur_node):
            next_nodes = IR_blocks_dfg[cur_node].childnode

        if len(next_nodes) == 0:
            stack_list.pop()
            visitorder.pop()

        else:
            if (len(set(next_nodes) - set(visited.keys())) == 0) and len(next_nodes & visited2[cur_node]) == 0:

                stack_list.pop()
                visitorder.pop()

            else:
                for i in next_nodes:
                    if i not in visited or i in visited2[cur_node]:
                        fathernodes = set()
                        usevar = {}
                        defined = {}
                        if IR_blocks_dfg.has_key(i):

                            fathernodes = IR_blocks_dfg[i].fathernode

                            usevar = IR_blocks_dfg[i].used

                            definevar = IR_blocks_dfg[i].defined

                        fdefinevarset = set()

                        findflag = False

                        allfdefinevarset = set()

                        for uvar in usevar:

                            if uvar not in definevar or usevar[uvar][0] < definevar[uvar][0]:
                                for fnode in fathernodes:
                                    fdefinevarset = set()
                                    if IR_blocks_dfg.has_key(fnode):
                                        fdefinevarset = IR_blocks_dfg[fnode].definedset
                                    allfdefinevarset |= fdefinevarset
                                    if uvar in fdefinevarset:
                                        res_graph.add_edge(fnode, i)
                                        print fnode, '->', i, "var:", uvar
                                for j in range(len(visitorder) - 1, -1, -1):
                                    visitednode = visitorder[j]
                                    temp_definedset = set()
                                    if IR_blocks_dfg.has_key(visitednode):
                                        temp_definedset = IR_blocks_dfg[visitednode].definedset
                                    if uvar in temp_definedset - allfdefinevarset:
                                        res_graph.add_edge(visitednode, i)
                                        allfdefinevarset |= temp_definedset
                                        print "fffff", visitednode, '->', i, "var:", uvar

                        visited[i] = '1'
                        visitorder.append(i)
                        if i in visited2[cur_node]:
                            visited2[cur_node].remove(i)
                            visited3[cur_node].add(i)
                        temp_childnode = set()
                        if IR_blocks_dfg.has_key(i):
                            temp_childnode = IR_blocks_dfg[i].childnode
                        visited2[cur_node] |= (set(temp_childnode) & set(visited)) - set(visited3[cur_node])
                        stack_list.append(i)
    return res_graph


def get_father_block(blocks, cur_block, yes_keys):
    father_block = None
    for temp_block in blocks:
        if temp_block.get_next() is cur_block.label:
            father_block = temp_block
    if father_block is None:
        return None
    is_Exist = False
    for yes_label in yes_keys:
        if ((str(father_block.label) + "L")).split(' ')[0].endswith(yes_label):
            is_Exist = True
    if not is_Exist:
        father_block = get_father_block(blocks, father_block, yes_keys)
        return father_block
    else:
        return father_block


def rebuild_graph(cur_block, blocks, IR_blocks, no_ir):
    yes_keys = list(IR_blocks.keys())
    no_keys = list(no_ir.keys())
    next_lable = (str(cur_block.label) + "L").split(' ')[0]
    father_block = get_father_block(blocks, cur_block, yes_keys)
    if not father_block is None:
        for yes_label in yes_keys:
            if ((str(father_block.label) + "L")).split(' ')[0].endswith(yes_label):
                for no_label in no_keys:
                    # print "222", next_lable, no_label
                    if next_lable.endswith(no_label):
                        IR_blocks[yes_label].pop()
                        IR_blocks[yes_label].extend(IR_blocks[no_label])
                        # print "<<<del", no_label
                        # print "<<<len", len(no_ir)
                        del (no_ir[no_label])
                        del (IR_blocks[no_label])
    return IR_blocks, no_ir


def dataflow_analysis(addr, block_items, DG):
    machine = guess_machine()
    mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira
    bs = bin_stream_ida()
    mdis = dis_engine(bs)
    mdis.dont_dis_retcall_funcs = []
    mdis.dont_dis = []
    ir_arch = ira(mdis.symbol_pool)
    blocks = mdis.dis_multiblock(addr)
    for block in blocks:
        ir_arch.add_block(block)
    # print ">>asm block",block

    IRs = {}
    for lbl, irblock in ir_arch.blocks.items():
        insr = []
        for assignblk in irblock:
            for dst, src in assignblk.iteritems():
                insr.append(str(dst) + "=" + str(src))
        # print ">>ir",(str(lbl)+"L"),insr
        IRs[str(lbl).split(' ')[0] + "L"] = insr
    # print	 "IRs.keys()",IRs.keys()

    IR_blocks = {}
    no_ir = {}
    for block in blocks:
        isFind = False
        item = str(block.label).split(' ')[0] + "L"
        for block_item in block_items:
            # print block_item
            if item.endswith(block_item):
                isFind = True
        if IRs.has_key(item):
            if isFind:
                IR_blocks[item] = IRs[item]
            else:
                IR_blocks[item] = IRs[item]
                no_ir[item] = IRs[item]
    # print "yes_ir : ",list(IR_blocks.keys())
    no_keys = list(no_ir.keys())
    # print "no_ir : ",no_keys
    for cur_label in no_keys:
        cur_block = None
        # print ""
        # print ""
        # print "find no_ir	 label is : ",cur_label
        for block in blocks:
            temp_index = str(block.label).split(' ')[0] + "L"
            # print block.label,temp_index
            if temp_index.endswith(cur_label):
                cur_block = block
        if not cur_block is None:
            # print "find no_ir ",cur_block
            IR_blocks, no_ir = rebuild_graph(cur_block, blocks, IR_blocks, no_ir)

    IR_blocks_toDFG = {}
    for key, value in IR_blocks.items():
        if len(key.split(':')) > 1:
            key = key.split(':')[0] + ":0x" + key.split(':')[1].strip()[2:].lstrip('0')
        # print "dg to dfg : ",key
        IR_blocks_toDFG[key] = value

    dfg = build_dfg(DG, IR_blocks_toDFG)
    dfg.add_nodes_from(DG.nodes())
    print "CFG edges <<", DG.number_of_edges(), ">> :", DG.edges()
    print "DFG edges <<", dfg.number_of_edges(), ">> :", dfg.edges()
    print "DFG nodes : ", dfg.number_of_nodes()
    return dfg

def mkdir_p(path):
    if os.path.exists(path):
        return
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

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
            if -int(5000) <= val <= int(5000):
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

def main():
    fea_path_origion = idc.ARGV[1]
    fea_path_temp = idc.ARGV[1] + os.sep + "temp"
    db_path = idc.ARGV[2]
    tokens = db_path.split(os.sep)
    print(db_path.split(os.sep))
    program, version, simple_db_name = os.sep.join(tokens[:-2]), tokens[-2], tokens[-1]
    print(program)
    fname_prefix = '_'.join(simple_db_name.split('.')[:-1])
    function_list_file = fea_path_origion + os.sep + "functions_list_fea.csv"

    textStartEA = 0
    textEndEA = 0
    for seg in idautils.Segments():
        if (idc.SegName(seg) == ".text"):
            textStartEA = idc.SegStart(seg)
            textEndEA = idc.SegEnd(seg)
            break


    func_bloc_str = ""


    func_instructions = ""


    block_instructions = ""

    for func in idautils.Functions(textStartEA, textEndEA):
        # Ignore Library Code
        flags = idc.GetFunctionFlags(func)
        if flags & idc.FUNC_LIB:
            continue

        cur_function_name = (fname_prefix + '_' + idc.GetFunctionName(func)).lower()
        fea_path = fea_path_origion

        func_bloc_str += cur_function_name
        single_func_instructions = []
        block_items = []
        DG = nx.DiGraph()
        allblock = idaapi.FlowChart(idaapi.get_func(func))
        for idaBlock in allblock:
            temp_str = str(hex(idaBlock.startEA))
            block_items.append(temp_str[2:])
            startEA = hex(idaBlock.startEA)
            func_bloc_str += "\t" + startEA
            DG.add_node(startEA)
            for succ_block in idaBlock.succs():
                DG.add_edge(hex(idaBlock.startEA), hex(succ_block.startEA))
            for pred_block in idaBlock.preds():
                DG.add_edge(hex(pred_block.startEA), hex(idaBlock.startEA))
            instructions = []
            curEA = idaBlock.startEA
            while curEA <= idaBlock.endEA:
                instruction = norm_func1(curEA)
                instructions.append(instruction)
                curEA = idc.NextHead(curEA, idaBlock.endEA)
            block_instructions += startEA + "\t" + ("\t".join(instructions)) + "\n"
            single_func_instructions.extend(instructions)

        func_bloc_str += "\n"
        func_instructions += cur_function_name + "\t" + ("\t".join(single_func_instructions)) + "\n"

        mkdir_p(fea_path)
        cfg_fp = open(fea_path + os.sep + str(cur_function_name) + "_cfg.txt", 'w+')
        for cfg_node in DG.nodes():
            cfg_str = str(cfg_node)
            for edge in DG.succ[cfg_node]:
                cfg_str = cfg_str + " " + edge
            cfg_str = cfg_str + "\n"
            cfg_fp.write(cfg_str)
        cfg_fp.close()

        dfg = dataflow_analysis(func, block_items, DG)
        dfg_file = fea_path + os.sep + str(cur_function_name) + "_dfg.txt"
        dfg_fp = open(dfg_file, 'w')
        for dfg_node in dfg.nodes():
                    dfg_str = dfg_node
                    for edge in dfg.succ[dfg_node]:
                        dfg_str = dfg_str + " " + edge
                    # print "dfg_str: ",dfg_str
                    dfg_str = dfg_str + "\n"
                    dfg_fp.write(dfg_str)
        dfg_fp.close()


        fea_file = fea_path + os.sep + str(cur_function_name) + "_fea.csv"
        fea_fp = open(fea_file, 'w')
        block_fea(allblock, fea_fp)

        function_str = str(cur_function_name) + "," + str(DG.number_of_nodes()) + "," + \
                       str(DG.number_of_edges()) + ","+ \
                       str(program) + "," + str(version) + "," + str(db_path) + ",\n"
        function_list_fp = open(function_list_file, 'a')
        function_list_fp.write(function_str)
        function_list_fp.close()


    base_dir = fea_path_origion
    mkdir_p(base_dir)
    func_block = base_dir + "\\" + (version + "_" + fname_prefix) + "_func_block.tsv"
    mode = "a"
    if not os.path.exists(func_block):
        mode = "w"
    with open(func_block, mode) as output:
        output.write(func_bloc_str)

    with open(base_dir + "\\" + (version + "_" + fname_prefix) + "_func_instructions.tsv", "w") as func_inst:
        func_inst.write(func_instructions)
    with open(base_dir + "\\" + (version + "_" + fname_prefix) + "_block_instructions.tsv", "w") as block_inst:
        block_inst.write(block_instructions)
    return

if __name__ == '__main__':
    main()
    idc.Exit(0)
