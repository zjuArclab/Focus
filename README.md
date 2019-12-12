# Focus: Function Clone Identiﬁcation on Cross-Platform

## Authors
Focus is designed by Lirong Fu, Penglei Zhao, Shouling Ji, Changchang Liu, Peiyu Liu, Fuzheng Duan, Zonghui Wang, Wenzhi Chen, and Ting Wang.

## [Dataset](https://drive.google.com/file/d/1wzsW91O06ZxDe1Vpp-eMJXEBcodoM_4r/view?usp=sharing) 
The dataset available from this page consists of four parts: Dataset1 is utilized to train the function embedding model and perform accuracy and efﬁciency tests; Dataset-2 is used to validate the effectiveness of Focus across different compilers. Dataset-3 is applied to evaluate the performance in vulnerability detection; Dataset-4 consists of vulnerable functions for the case study of vulnerability search. Next, we describe each dataset in detail as follows.

- Dataset-1. Dataset-1 includes binary ﬁles that are compiled from OpenSSL-1.0.1f and Busybox-1.27.0 under eight different architectures, including MIPS32, MIPS64, ARM, AARCH64, X86, AMD64, POWERPC32, and POWERPC64, with optimization levels O0-O3 by gcc-5.4. In total, we obtain 296,714 binary functions.

- [Dataset-2](https://github.com/nimrodpar/esh-dataset-1523). Dataset-2 consists of binary ﬁles compiled from Coreutils, OpenSSL, Bash, ntpd, QEMU, WireShark, and Wget, which is compiled by gcc-4.9, gcc-4.8, gcc-4.6, clang-3.5, clang-3.4, icc-15.0.1, and icc-14.0.4. This open-sourced 2 dataset is used to ﬁnd similar code when it has been compiled using different compilers by Yaniv David et al.

- Dataset-3. we construct a dataset that consists of binary ﬁles compiled from Binutils-2.30, Coreutils-8.29 and Findutils-4.6.0 under eight architectures with optimization levels O0-O3 by gcc-5.4, as described in Dataset-1. 

- Dataset-4. This dataset includes vulnerable functions obtained from CVE. In total, it consists of 121 real world vulnerable functions.


### Feature Engineering
We map the raw data of binary code to machine learning features through AFG. Firstly, we generate CFG and DFG for binary code, which can be used to represent the structural features of a program. Second, we design a customized IE model to automatically generate the instruction embeddings of binary code, which contain comprehensive semantic features of binary code. Before we obtain instruction embeddings, we need to normalize the corresponding instructions for better performance.

- **CFG extractor**: we implement an IDA-pro 7.0  plugin to obtain CFG.
- **DFG extractor**: we leverage an open source tool Miasm2 to extract DFG.
- **IE extractor**: ae build a customized IE model motivated by word2vec.





### Graph Embedding
By creatively employing a multi-head attention mechanism from the CV ﬁeld, we design a novel semanticaware GTN to obtain accurate embedding vector of each binary function by capturing the most critical features during the embedding process, which is based on GNN.

- **Semantic-aware GTN**: we uniquely apply the multi-head attention mechanism to automatically assign various weights to different features.
- **Siamese Neural Network**: we make use of the classic architecture of the siamese neural network to learn parameters of our Focus.


## Code

### Requirements

- tensorflow
- numpy
- IDA-pro 7.0
- Miasm2



### Generate Feature

#### Generate CFG and DFG
```
python command.py [options] -i input_folder
```


- **input_folder**: String - The data folder saving all binary information.

Options:

- **-o**: String - The output file for training embedding model
- **-e**: String - The file saving all error information
- **-m**: String - The file saving the map information (int --> instruction (int list))

#### Generate IE
```
python train_embed.py -i input_path
```


- **input_path**: String - The input file for training embedding model 

Options:
- **-o**: String - The output folder saving the trained embedding information
- **-tn**: Integer - Number of threads
- **-sw**: Integer - Saving frequency (Number of epochs). The trained information will be saved every several epochs.





### Train Embedding Model

#### Prepare the input file for training embedding model
```
python Gen_training_set.py 
```


- **PROGRAMS**: String - The programs used to train the model. 
- **ARCHS**: String - The architectures choosed to train the model.
- **OPT_LEVELS**: String - The optimization-level choosed to train the model.
- **CFG_DFG_FEA**: String - The path used to store the feature of programs.
- **DATASET_TRAIN**: String - The path used to store training data.
- **DATASET_VALID**: String - The path used to store validation data.
- **DATASET_TEST**: String - The path used to store testing data.


```
python Gen_tfrecord.py 
```
- **TFRECORD_TRAIN**: String - The path used to store training tfrecord.
- **TFRECORD_VALID**: String - The path used to store validation tfrecord.
- **TFRECORD_TEST**: String - The path used to store testing tfrecord.




#### Train embedding model
```
python Train_model.py [options] -P dimension -H heads -T iterations -epoch epochs:
```


Options:

- **TRAIN_DATASET_NUM**: The number of training functions.
- **MODEL_DIR**: The path used to store model.
- **STATIS_DIR**: The path used to store testing statics.

- **-en**: The name of experiment. 
- **-GPU**: cuda visible devices. (Default value: 0)
- **-epoch**: Number of epochs. (Default value: 5)
- **-H**: Number of attention heads.(Default value: 2)
- **-P**: Number of embedding dimension in GTN. (Default value: 64)
- **-T**: Number of iterations (Default value: 10)



## Disclaimer
The code is research-quality proof of concept, and is still under development for more features and bug-fixing.

## References
Focus: Function Clone Identiﬁcation on Cross-Platform

Lirong Fu, Penglei Zhao, Shouling Ji, Changchang Liu, Peiyu Liu, Fuzheng Duan, Zonghui Wang, Wenzhi Chen, and Ting Wang.

## Project Members
Lirong Fu, Penglei Zhao, Shouling Ji, Changchang Liu, Peiyu Liu, Fuzheng Duan, Zonghui Wang, Wenzhi Chen, and Ting Wang.
