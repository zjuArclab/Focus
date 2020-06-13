import os
import idaapi
import idautils
import idc
import config

functions = []

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
            if -int(500) <= val <= int(500):
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

def norm_func4(head):
    inst = '' + idc.GetMnem(head)
    idaapi.decode_insn(head)
    i = 0
    for i,v in enumerate(idaapi.cmd.Operands):
        type_op = v.type
        if i > 1:
            inst += ','
        if type_op == idc.o_void:
            break
        elif type_op == idc.o_mem:
            inst += ' [MEM]'
        elif type_op == idc.o_imm:
            val = idc.GetOperandValue(head, i)
            #if -int(5000) <= val <= int(5000):
            if -int(500) <= val <= int(500):
                inst += ' ' + str(hex(val))
            else:
                inst += ' HIMM'
        # 0x28+var_8($sp) type oprands
        # mov eax,[ebx+18h]
        elif type_op == idc.o_displ:
        	#val = idc.GetOpnd(head,i)
        	#offset_index = val.find('+')
        	#val = val[:offset_index] + '+OFFSET]'
        	#inst += val    # for x64 inst 
            val = idc.GetOpnd(head, i)
            reg_index = val.find('($')  # only for mips
            val = val[reg_index:]
            inst += ' [OFFSET]' + val
        elif type_op == idc.o_near:
            inst += ' [LOC]'
        else:
            inst += ' ' + idc.GetOpnd(head, i)

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

def main():
    global functions 
    program_ver_arch_opt = idc.ARGV[2]
    program = idc.ARGV[3]
    PROGRAM = idc.ARGV[1]
    parent_dir = os.path.join(config.Normalize_INST_DIR, config.Normalize_type, PROGRAM, program_ver_arch_opt)
    print(parent_dir)
    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)
    norm_inst_dir = parent_dir + os.sep + 'function_norm_inst/'
    if not os.path.exists(norm_inst_dir):
        os.makedirs(norm_inst_dir)
    
    textStartEA = 0
    textEndEA = 0
    res = []
    for seg in idautils.Segments():
        if (idc.SegName(seg)[:5] == ".text"):
            textStartEA = idc.SegStart(seg)
            textEndEA = idc.SegEnd(seg)
            print(str(hex(textStartEA)))
            print(str(hex(textEndEA)))
            print('\n')
        for func in idautils.Functions(textStartEA, textEndEA):
            flags = idc.GetFunctionFlags(func)
            if flags & idc.FUNC_LIB:
                print hex(func), "FUNC_LIB", idc.GetFunctionName(func)
                continue
            func_name = idc.GetFunctionName(func)

            # replace '.' in program to '_'
            program = '_'.join(program.split('.'))
            cur_function_name = program + '_' + func_name
            if len(cur_function_name) > 130:
                cur_function_name = cur_function_name[:130]
            if ':' in cur_function_name:
                cur_function_name = '_'.join(cur_function_name.split(':'))
            if cur_function_name.lower() in functions:
                pass
            else:
                functions.append(cur_function_name.lower())
                norm_inst_file = norm_inst_dir + os.sep + str(cur_function_name) + "_norm.csv"
                norm_fp = open(norm_inst_file, 'w')

                tmp = []
                allblock = idaapi.FlowChart(idaapi.get_func(func))
                for block in allblock:
                    one_block_norms = []
                    curEA = block.startEA
                    while curEA <= block.endEA:
                        #print config.Normalize_type
                        cur_norm_inst = eval(config.Normalize_type)(curEA)
                        tmp.append(cur_norm_inst)
                        one_block_norms.append(cur_norm_inst)
                        curEA = idc.NextHead(curEA, block.endEA)
                        
                    one_block_norm_str = '\t'.join(one_block_norms)
                    one_block_norm_str = str(hex(block.startEA)) + '\t' + one_block_norm_str + '\n'
                    norm_fp.write(one_block_norm_str)
                norm_fp.close()
                res.append(tmp)

    file_name = os.path.join(parent_dir, program + '.csv')
    #with open(file_name, 'w') as f:
    #    for line in res:
    #        f.write('\t'.join(line))
    #        f.write('\n')

# redirect output into a file, original output is the console.
def stdout_to_file(output_file_name, output_dir=None):
    if not output_dir:
        output_dir = os.path.dirname(os.path.realpath(__file__))
    output_file_path = os.path.join(output_dir, output_file_name)
    print output_file_path
    print "original output start"
    # save original stdout descriptor
    orig_stdout = sys.stdout
    # create output file
    f = file(output_file_path, "w")
    # set stdout to output file descriptor
    sys.stdout = f
    return f, orig_stdout

if __name__ == '__main__':
    #f, orig_stdout = stdout_to_file("output_" + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())) + ".txt")
    main()
    #sys.stdout = orig_stdout  # recover the output to the console window
    #f.close()
    idc.Exit(0)

