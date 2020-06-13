#!/usr/bin/python
# -*- coding: UTF-8 -*-

import os


# You need to specify an IDA Path here
IDA32_DIR = "Your\\Path\\IDA 7.0\\ida.exe"
IDA64_DIR = "Your\\Path\\IDA 7.0\\ida64.exe"
# e.g.
# IDA32_DIR = "C:\\Program Files\\IDA 7.0\\ida.exe"
# IDA64_DIR = "C:\\Program Files\\IDA 7.0\\ida64.exe"



# The path of the current python files i.e. Gen_features
CODE_DIR  = "Your\Path\Current Directory\Gen_features"
#e.g.
# CODE_DIR  = "D:\\binary-similarity\\Extract_binary_feature\\Gen_features"


# The path that you store your binary code
O_DIR = "Your\Path\of\Binary\Code"
#e.g.
# O_DIR = "L:\\data\\all_software"




# The path of all the idb files
IDB_DIR = "Your\Path\That\Stores\The\Output\IDB Files"
#e.g.
# IDB_DIR =  O_DIR



# The  path of the cfg files & feature files [we store the features that extracted in Gemini and VulSeeker]
FEA_DIR = "Your\Path\That\Stores\The\Output\CFG\And\Features"
#e.g.
# FEA_DIR = "F:\\HUAWEI\\all_software\\all_software_features"


#  You need to determine whether to generate idb files
STEP1_GEN_IDB_FILE = True/False

#e.g.
# STEP1_GEN_IDB_FILE = False

# You need to specify the name of program in step-1

STEP1_PORGRAM_ARR=['Program']

# e.g.
# STEP1_PORGRAM_ARR=['all_software']


# You can choose one of the following STEP2_GEN_FEA_CFG_DFG or STEP2_GEN_FEA_CFG
#  You need to determine whether to generate feature, CFG, and DFG
STEP2_GEN_FEA_CFG = True/False


#  You need to determine whether to generate DFG
STEP2_GEN_DFG = True/False


# You need to specify the name of program in step-2
 STEP2_PORGRAM_ARR=['Program']

#e.g.
#STEP2_PORGRAM_ARR=['all_software']


