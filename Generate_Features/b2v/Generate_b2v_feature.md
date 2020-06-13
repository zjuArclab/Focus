## **Generate Instruction embedding for each Basic Block (BB) and Obtain BB embedding** ##

### How To ###

* 1_gen_normed_stream.py is used to disassembly binary code and generate normed instruction. which is stored in norm.csv.

* 2_gen_i2v_model.py  trains a Word2vec modle by the  normed instruction.

* 3_b2v.py generates Instruction embedding （i2v) and BB embedding, which is stored in fea.csv.

* config.py determines some configurations of this program.

* command.py executes 1_gen_normed_stream.py and 2_gen_i2v_model.py, and 3_b2v.py, which requires the input of binary code and output fea.csv.

* config_for_feature.py sets different kinds of instructions such as jmp, move, and so on, which is used to calculate the basic block features of each function. 


###  Work Flow ###

0. You need to execute Gen_cfg/1_gen_idb_file.py to generate .idb files.

1. You need to modify config.py to set the path of your IDA, the path of the binary code，the path to store the extracted norm.csv, and so on. 

2. python command.py


