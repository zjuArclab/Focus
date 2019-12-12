import os
import idaapi
import idautils
import idc
import config


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
            #if -int(5000) <= val <= int(5000):
            #if -int(500) <= val <= int(500):
            #if -int(50000) <= val <= int(50000):
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


# def norm_func4(head):
#     inst = '' + idc.GetMnem(head)
#     num_operands = op_count(head)
#     if inst
#     for i in range(num_operands):
#         type_op = idc.GetOpType(head, i)
#         if type_op == idc.o_void:
#             break
#         elif type_op == idc.o_mem:
#             inst += ' [MEM]'
#         elif type_op == idc.o_imm:
#             val = idc.GetOperandValue(head, i)
#             if idc.SegName(val) == '.rodata' and (idc.GetOpType(val)) == 'char[]' and i == 1:
#                 inst += ' ' + str('STR')
#             else:
#                 inst += ' 0'
#         else:
#             inst += ' ' + idc.GetOpnd(head, i)
#
#         if num_operands > 1:
#             inst += ','
#
#     if ',' in inst:
#         inst = inst[:-1]
#     inst = inst.replace(' ', '_')
#     return str(inst)

if __name__ == '__main__':
    print("#############################################")
    textStartEA = 0
    textEndEA = 0
    for seg in idautils.Segments():
        if (idc.SegName(seg) == ".text"):
            textStartEA = idc.SegStart(seg)
            textEndEA = idc.SegEnd(seg)
            break
    res = []
    for func in idautils.Functions(textStartEA, textEndEA):
        flags = idc.GetFunctionFlags(func)
        if flags & idc.FUNC_LIB:
            print hex(func), "FUNC_LIB", idc.GetFunctionName(func)
            continue
        func_name = idc.GetFunctionName(func)
        tmp = []
        allblock = idaapi.FlowChart(idaapi.get_func(func))
        for block in allblock:
            curEA = block.startEA
            while curEA <= block.endEA:
                tmp.append(eval(config.Normalize_type)(curEA))
                curEA = idc.NextHead(curEA, block.endEA)
        res.append(tmp)

    program_ver_arch_opt = idc.ARGV[2]
    program = idc.ARGV[3]
    PROGRAM = idc.ARGV[1]
    parent_dir = os.path.join(config.Normalize_INST_DIR, config.Normalize_type, PROGRAM, program_ver_arch_opt)
    print(parent_dir)
    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)
    file_name = os.path.join(parent_dir, program + '.csv')
    with open(file_name, 'w') as f:
        for line in res:
            f.write('\t'.join(line))
            f.write('\n')
    idc.Exit(0)

