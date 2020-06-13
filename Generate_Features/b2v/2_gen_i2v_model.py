import os
import time
import glob
from tqdm import tqdm
import gensim
import multiprocessing
import config


def Generate_dataset():
    Normalize_INST_DIRS = []
    for program in config.PROGRAMS:
        files = glob.glob(os.path.join(config.Normalize_INST_DIR, config.Normalize_type, program, '*'))
        for file in files:
            print(file)
            if not ('all' in config.ARCHS and 'all' in config.OPT_LEVELS):
                opt_level = file.split('_')[-1]
                arch = file.split('_')[-2]
                if not (((arch in config.ARCHS) and (opt_level in config.OPT_LEVELS )) or (('all' in  config.ARCHS) and (opt_level in config.OPT_LEVELS )) or ((arch in  config.ARCHS) and ('all' in config.OPT_LEVELS )) or (('all' in  config.ARCHS) and ('all' in config.OPT_LEVELS ))):
                    continue
            sub_files = glob.glob(os.path.join(file, 'function_norm_inst', '*.csv'))
            for sub_file in sub_files:
                Normalize_INST_DIRS.append(sub_file)
                    #print(sub_file)
    #print (Normalize_INST_DIRS)
    return Normalize_INST_DIRS


class Sentences(object):

    def __init__(self, files):
        self.files = files


    def __iter__(self):
        for file in tqdm(self.files):
            with open(file, 'r') as f:
                for line in f.readlines():
                    line = line.strip('\n')
                    yield line.split('\t')[1:]


if __name__ == '__main__':
    cores = multiprocessing.cpu_count()
    Normalize_INST_DIRS = Generate_dataset()
    sentences = Sentences(Normalize_INST_DIRS)
    print('Setting up parameters...')
    model = gensim.models.Word2Vec(window=config.windows_size,
                                   size=config.embedding_size,
                                   min_count=config.min_count_num,
                                   workers=cores - 1)
    print('build vocabulary...')
    t = time.time()
    model.build_vocab(sentences, progress_per=10000)
    print('Time to build vocab: {} mins'.format(round((time.time() - t) / 60, 2)))

    print('train i2v model...')
    t = time.time()
    model.train(sentences, total_examples = model.corpus_count, epochs = 30, report_delay = 1)
    print('Time to train the model: {} mins'.format(round((time.time() - t) / 60, 2)))

    model.init_sims(replace = True)

    print("Save model in {}".format(config.SAVE_WORD2VEC_MODEL))
    model.save(config.SAVE_WORD2VEC_MODEL)

