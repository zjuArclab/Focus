## **Extract the control flow graph (CFG)， data flow graph (DFG), and the features  (described in Gemini and Vluseeker)   of the given binary code** ##

### How To ###
* 1_gen_idb_file.py is used to generate .idb files for binary code through IDA pro-7.0

* 2_gen_features_cfg.py is intended for extracting CFG, DFG, and basick block features of binary code (stored in .i64 files). For each binary function, CFG is stored in cfg.txt; DFG is stored in dfg.txt; Features are stored in fea.csv. The extracting time is stored in program_mfe_extractor_time.json, program_dfg_extractor_time.json, program_cfg_extractor_time.json in FEA_DIR. 

* config.py determines some configurations of this program

* command.py executes 1_gen_idb_file.py and 2_gen_features_cfg.py, which requires the input of binary code and output cfg.txt, dfg.txt and fea.csv.

* config_for_feature.py sets different kinds of instructions such as jmp, move, and so on, which is used to calculate the basic block features of each function. 

### Work Flow ###

1. You need to modify config.py to set the path of your IDA, the path of the binary code，the path to store the extracted cfg.txt and fea.csv, and so on. 

2. python command.py 


### Notice ###

We name binary as Program_Architecture_Opt (as shown in How-To-Define-BinaryCode-Path-1, each folder stores all the execuatble files the compiled from the specific Arch and Opt)

Binary code is stored in O_DIR\Program\ Program_Architecture_Opt.
For instance, (1) in How-To-Define-BinaryCode-Path-1, the  O_DIR should be L:\Huawei\data\all_software, Program should be ["all_software"]. There is only one folder all_software in O_DIR  (2) in How-To-Define-BinaryCode-Path-2, the  O_DIR should be L:\VulSeeker\VulSeeker\0_lib, Program should be ["openssl", "busybox"]. There are two folders  ["openssl", "busybox"] in O_DIR.

program_cfg_extractor_time.json records time as described in Extracting_time.PNG, in which the key stands for the number of basic block, and the values are time.