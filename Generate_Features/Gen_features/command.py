#!/usr/bin/python
# -*- coding: UTF-8 -*-
import config
import os
import subprocess
import glob
import shutil
import sys
import time
t0 = time.clock()
if config.STEP1_GEN_IDB_FILE:
    print "step1. convert binary code to idb file"
    subprocess.call(["python", config.CODE_DIR+ os.sep + "1_gen_idb_file.py"])

if config.STEP2_GEN_FEA_CFG:
    print "step2. generate feature, CFG, or DFG"

    if not os.path.exists(config.FEA_DIR):
        os.mkdir(config.FEA_DIR)

    for program in config.STEP2_PORGRAM_ARR:
        tempdir = config.FEA_DIR + os.sep + str(program)
        if not os.path.exists(tempdir):
            os.mkdir(tempdir)

        for version in os.listdir(config.IDB_DIR + os.sep + program):
            curFeaDir = config.FEA_DIR + str(os.sep) + str(program) + str(os.sep) + str(version)
            curBinDir = config.IDB_DIR + str(os.sep) + str(program) + str(os.sep) + str(version)
            if not os.path.exists(curFeaDir):
                os.mkdir(curFeaDir)
            filters = glob.glob(curBinDir + os.sep + "*.idb")
            filters = filters + (glob.glob(curBinDir + os.sep + "*.i64"))
            for i in filters:
                if i.endswith("idb"):
                    print config.IDA32_DIR+" -S\""+config.CODE_DIR+ os.sep + "2_gen_features_cfg.py "+curFeaDir+"  "+i +"  "+ str(program) +"  "+ str(version) +"\"  "+i+"\n"
                    subprocess.call(config.IDA32_DIR+" -A  -S\""+config.CODE_DIR+"\\2_gen_features_cfg.py "+curFeaDir+" "+i +"  "+ str(program) +"  "+ str(version)  + "\"  "+i )
                else:
                    print config.IDA64_DIR+" -S\""+config.CODE_DIR+ os.sep + "2_gen_features_cfg.py "+curFeaDir+"  "+i +"  "+ str(program) +"  "+ str(version) +"\"  "+i+"\n"
                    subprocess.call(config.IDA64_DIR+" -S\""+config.CODE_DIR+"\\2_gen_features_cfg.py "+curFeaDir+" "+i +"  "+ str(program) +"  "+ str(version)  + "\"  "+i )


print (time.clock()-t0)