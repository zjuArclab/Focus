import os

###############################  1_gen_normed_stream#####################################################


# You need to specify an IDA Path here
IDA32_DIR = "Your\\Path\\IDA 7.0\\ida.exe"
IDA64_DIR = "Your\\Path\\IDA 7.0\\ida64.exe"
PYTHON_DIR = "Your\\Path\\python27-x64\\python.exe"
# e.g.
# IDA32_DIR = "C:\\Program Files\\IDA 7.0\\ida.exe"
# IDA64_DIR = "C:\\Program Files\\IDA 7.0\\ida64.exe"
# PYTHON_DIR = 'C:\\python27-x64\\python.exe'

# The path of the current python files i.e. b2v
CODE_ROOT_DIR  = "Your\Path\Current Directory\\b2v"
#e.g.
# CODE_ROOT_DIR  = FEA_DIR = "Your\Path\That\Stores\The\Output\CFG\And\Features"


# The path that you store your binary code
O_DIR = "Your\Path\of\Binary\Code"
#e.g.
# O_DIR = "L:\\data\\all_software"

# When we extract CFG and Feature by Gen_cfg, we can obtain funclist.csv which stores the function list of the binary
# file.  We read funclist.csv from FEA_DIR to obtain function list and according the function list, we search 
# Normalize_INST_DIR to obtain the corresponding normed instruction stream of the function. Finally,
# we can generate insruction embedding and BB embedding by input the normed instruction stream to
# the trained model.

# FEA_DIR is used to find funclist.csv
FEA_DIR = 'Your\\Path\\That\\Stores\\CFG\\Obtained\\in\\Gen_cfg'
# e.g.
# FEA_DIR = "F:\\HUAWEI\\all_software\\all_software_features"


# You need to specify the name of program in step-1
PROGRAMS=['Program']
# e.g.
# PROGRAMS=['all_software'] /['busybox','openssl']

# You need to specify the path the stores the normed instruction stream.
Normalize_INST_DIR = "Your\\Path\\That\\Stores\\normed_inst_stream"
#e.g.
# Normalize_INST_DIR="L:\\data\\all_software\\normed_inst_stream"

# You need o specify the type of normalization
Normalize_type='Norm_Type' 
#e.g.
# Normalize_type='norm_func1' 

# You need to determine if generate normed inst stream 
GEN_NORMED_STREAM = True / False
#e.g.
# GEN_NORMED_STREAM = True

###############################cinfigure for gen_i2v_model#####################################################
GEN_I2V_MODEL = False 
OPT_LEVELS = ['all']  # ['o0','o1','o2','o3']
ARCHS = ['all'] # ['all'] ['arm32'],['aarch64'],['mips32'],['mips64'],['powerpc32'],['powerpc64'],['x86'],['x64']
embedding_size = 50
windows_size = 8
min_count_num =1
SAVE_WORD2VEC_MODEL = os.path.join(Normalize_INST_DIR, Normalize_type, '[' + '_'.join(PROGRAMS) + ']_[' + '_'.join(ARCHS) + ']_[' + '_'.join(OPT_LEVELS) + ']'+ '_i2v'+'.model')

###############################cinfigure for gen_b2v#####################################################
GEN_B2V = False
# the dir to save generated b2v features
b2v_DIR =os.path.join(Normalize_INST_DIR,Normalize_type,'[' + '_'.join(PROGRAMS) + ']')  # the dir to save generated b2v features
# the oov of the program, which generate by word2vec model
OOV_path = os.path.join(b2v_DIR, 'oov.txt') 
# The number of all the instruvtions and oov
COUNT_path = os.path.join(b2v_DIR,'count.txt')
