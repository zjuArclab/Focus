import os
import glob
import shutil
import subprocess
from tqdm import tqdm
import config
import time
from collections import defaultdict

Normalization_time=defaultdict(list)
Training_model_time=defaultdict(list)
b2v_time=defaultdict(list)
############################### for gen_normed_stream#####################################################
if config.GEN_NORMED_STREAM:
    gen_inst_stream = os.path.join(config.CODE_ROOT_DIR, '1_gen_normed_stream.py')
    for PROGRAM in config.PROGRAMS:
        files = glob.glob(os.path.join(config.BINARY_ROOT_DIR, PROGRAM,  '*', '*.i*'))
        for file in tqdm(files):
            program_ver_arch_opt, program = file.split('\\')[-2:]
            program = program[:-4]
            print program_ver_arch_opt
            t_norm_start = time.time()
            if file.endswith('idb'):
                subprocess.call(config.IDA32_DIR + ' -S\"' + gen_inst_stream + ' ' + PROGRAM + ' ' + program_ver_arch_opt + ' ' + program + '\" ' + file)
            else:
                subprocess.call(config.IDA64_DIR + ' -S\"' + gen_inst_stream + ' ' + PROGRAM + ' ' + program_ver_arch_opt + ' ' + program + '\" ' + file)
            Normalization_time[file]=(str(time.time() - t_norm_start))
###############################gen_i2v_model#####################################################
if config.GEN_I2V_MODEL:
    t_train_start = time.time()
    gen_i2v= os.path.join(config.CODE_ROOT_DIR, '2_gen_i2v_model.py')
    subprocess.call(config.PYTHON_DIR + ' ' +gen_i2v)
    Training_model_time["train"] = str(time.time() - t_train_start)
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

        for version in os.listdir(config.Normalize_INST_DIR + os.sep + config.Normalize_type + os.sep + program):
            curFeaDir = config.b2v_DIR + str(os.sep) + str(program) + str(os.sep) + str(version)
            curBinDir = config.BINARY_ROOT_DIR + str(os.sep) + str(program) + str(os.sep) + str(version)
            if not os.path.exists(curFeaDir):
                os.makedirs(curFeaDir)
            print "python " + config.CODE_ROOT_DIR + os.sep + "3_b2v.py -fea_path " + curFeaDir + " -program " + str(program) + " -version " + str(version) + "\n"
            t_b2v_start = time.time()
            subprocess.call("python " + config.CODE_ROOT_DIR + os.sep + "3_b2v.py -fea_path " + curFeaDir + " -program " + str(program) + " -version " + str(version))
            b2v_time[curFeaDir] =  str(time.time() - t_b2v_start)

