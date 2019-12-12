import os
import glob
import shutil
import subprocess
from tqdm import tqdm
import config

############################### for gen_normed_stream#####################################################
if config.GEN_NORMED_STREAM:
    gen_inst_stream = os.path.join(config.CODE_ROOT_DIR, '1_gen_normed_stream.py')
    for PROGRAM in config.PROGRAMS:
        files = glob.glob(os.path.join(config.BINARY_ROOT_DIR, PROGRAM,  '*', '*.i64'))
        for file in tqdm(files):
            program_ver_arch_opt, program = file.split('\\')[-2:]
            program = program[:-4]
            print program_ver_arch_opt
            print config.IDA64_DIR + ' -S\"' + gen_inst_stream + ' ' + PROGRAM + ' ' + program_ver_arch_opt + ' ' + program + '\" ' + file
            subprocess.call(config.IDA64_DIR + ' -S\"' + gen_inst_stream + ' ' + PROGRAM + ' ' + program_ver_arch_opt + ' ' + program + '\" ' + file)

###############################gen_i2v_model#####################################################
if config.GEN_I2V_MODEL:
    gen_i2v= os.path.join(config.CODE_ROOT_DIR, '2_gen_i2v_model.py')
    subprocess.call(config.PYTHON_DIR + ' ' +gen_i2v)

###############################gen_b2v_model#####################################################
if config.GEN_B2V:
    print(config.SAVE_WORD2VEC_MODEL)
    print(config.OOV_path)
    if not os.path.exists(config.b2v_DIR):
        os.makedirs(config.b2v_DIR)
    for program in config.PROGRAMS:
        tempdir = config.b2v_DIR + os.sep + str(program)
        if not os.path. exists(tempdir):
            os.mkdir(tempdir)
        # if program == 'busybox':
        #     continue
        for version in os.listdir(config.BINARY_ROOT_DIR + os.sep + program):
            curFeaDir = config.b2v_DIR + str(os.sep) + str(program) + str(os.sep) + str(version)
            curBinDir = config.BINARY_ROOT_DIR + str(os.sep) + str(program) + str(os.sep) + str(version)
            if not os.path.exists(curFeaDir):
                os.makedirs(curFeaDir)
            filters = glob.glob(curBinDir + os.sep + "*.idb")
            filters = filters + (glob.glob(curBinDir + os.sep + "*.i64"))
            print "filters: "
            print filters
            # filters = ["G:\\VulSeeker\\VulSeeker\\0_Libs\\openssl\\openssl-1.0.1f_x64_o3\\openssl.i64"]
            for i in filters:
                # function.id, block.id, instruction.id
                # idaq -S"2_gen_features.py C:\\Users\\yx\\Desktop\\dataset\\3_Featrue\\openssl\\openssl_1_0_1f_arm_o0 tty.idb program version"  tty.idb
                # print i
                if i.endswith("idb"):
                    print config.IDA32_DIR + " -S\"" + config.CODE_ROOT_DIR + os.sep + "3_b2v.py " + curFeaDir + "  " + i + "  " + str(program) + "  " + str(version) + "\"  " + i + "\n"
                    # os.popen(config.IDA32_DIR+"   -S\""+config.CODE_DIR+ os.sep + "2_gen_features.py "+curFeaDir+" "+i +"  "+ str(program) +"  "+ str(version)  + "\"  "+i)
                    subprocess.call(config.IDA32_DIR + " -A  -S\"" + config.CODE_ROOT_DIR + "\\3_b2v.py " + curFeaDir + " " + i + "  " + str(program) + "  " + str(version) + "\"  " + i)
                    # config.IDA32_DIR + " -A  -S\"" + config.CODE_DIR + "\\2_gen_features.py " + curFeaDir + " " + i + "  " + str(program) + "  " + str(version) + "\"  " + i
                else:
                    print config.IDA64_DIR + " -S\"" + config.CODE_ROOT_DIR + os.sep + "3_b2v.py " + curFeaDir + "  " + i + "  " + str(program) + "  " + str(version) + "\"  " + i + "\n"
                    # os.popen(config.IDA64_DIR+" -S\""+config.CODE_DIR+ os.sep + "2_gen_features.py "+curFeaDir+" "+i +"  "+ str(program) +"  "+ str(version)  + "\"  "+i)
                    subprocess.call(config.IDA64_DIR + " -S\"" + config.CODE_ROOT_DIR + "\\3_b2v.py " + curFeaDir + " " + i + "  " + str(program) + "  " + str(version) + "\"  " + i)
                    # config.IDA64_DIR + " -S\"" + config.CODE_DIR + "\\2_gen_features.py " + curFeaDir + " " + i + "  " + str(program) + "  " + str(version) + "\"  " + i



