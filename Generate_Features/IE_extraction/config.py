import os

###############################  1_gen_normed_stream#####################################################
IDA64_DIR = "C:\\Program Files\\IDA 7.0\\ida64.exe"
IDA32_DIR = 'C:\\Program Files\\IDA 7.0\\ida32.exe'
PYTHON_DIR = 'C:\\python27-x64\\python.exe'
CODE_ROOT_DIR = 'D:\\Binary_Similarity\\Focus\code\\IE_extraction'
BINARY_ROOT_DIR = 'D:\\Binary_Similarity\\Focus\data\\Binary'
PROGRAMS = ["openssl","busybox"]
Normalize_INST_DIR = 'D:\\Binary_Similarity\\Focus\\data\\Features\\normed_inst_stream500'
Normalize_type='norm_func1'
GEN_NORMED_STREAM = False
FEA_DIR = "D:\\Binary_Similarity\\Focus\\data\\Features"
GEN_I2V_MODEL = True
OPT_LEVELS = ['all']
ARCHS = ['all']
embedding_size = 50
windows_size = 8
min_count_num =1
SAVE_WORD2VEC_MODEL = os.path.join(Normalize_INST_DIR, Normalize_type, '[' + '_'.join(PROGRAMS) + ']_[' + '_'.join(ARCHS) + ']_[' + '_'.join(OPT_LEVELS) + ']'+ '_i2v_'+'.model')


###############################cinfigure for gen_b2v#####################################################
GEN_B2V = True
b2v_DIR =os.path.join(Normalize_INST_DIR,Normalize_type)
OOV_path = os.path.join(b2v_DIR, 'oov.txt')
