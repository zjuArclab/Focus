import os
import sys
import time
import json
import pickle
from tqdm import tqdm
import tensorflow as tf
import numpy as np
from sklearn.metrics import roc_curve
from sklearn.metrics import auc
import core.config as config
from core.config import logging
from core.tools import save_dict_to_csv

import argparse

parser = argparse.ArgumentParser(description = 'Train Focus')

parser.add_argument('-en', '--exp_name', \
                    help = 'name or goal of this experiment', \
                    type = str, \
                    required=True)
parser.add_argument('-T', '--T', \
                    help = 'GNN iters of capturing neighbor infomations', \
                    type = int, \
                    default = 10) # 1 2 3 4 5 6 7 8 9 10
parser.add_argument('-H', '--H', \
                    help = 'Attention multi head', \
                    type = int, \
                    default = 2) # 1 2 3 4 5 6 7 8
parser.add_argument('-P', '--P', \
                    help = 'graph embedding size', \
                    type = int, \
                    default = 64) # 2 8 16 21 64 128 256
parser.add_argument('-epoch', '--epoch', \
                    help = 'train epoch', \
                    type = int, \
                    default = config.NUM_EPOCH)
parser.add_argument('-GPU', '--GPU', \
                    help = 'cuda visible devices', \
                    type = str, \
                    default = '0')

args = parser.parse_args()

os.environ["CUDA_VISIBLE_DEVICES"] = args.GPU
T = args.T # iteration
H = args.H # attention multi head
P = args.P # embedding_size
hid_units = [P for i in range(args.T)]
n_heads = [H for i in range(args.T)]
n_heads.append(1)
D = config.WORD2VEC_EMBEDDING_SIZE
# D = 8
B = 64 # batch size
lr = 0.0001 # 
num_epoch = args.epoch

decay_steps = 10
decay_rate = 0.0001
snapshot = 1 # validate models between num epoch
display_step = 20

train_num = config.TRAIN_DATASET_NUM
valid_num = int(train_num / 10.0)
test_num = int(train_num / 10.0)

def adj_to_bias(adj, sizes, nhood=1):
    nb_graphs = adj.shape[0]
    mt = np.empty(adj.shape)
    for g in range(nb_graphs):
        mt[g] = np.eye(adj.shape[1])
        for _ in range(nhood):
            mt[g] = np.matmul(mt[g], (adj[g] + np.eye(adj.shape[1])))
        for i in range(sizes[g]):
            for j in range(sizes[g]):
                if mt[g][i][j] > 0.0:
                    mt[g][i][j] = 1.0
    return -1e9 * (1.0 - mt)


def get_batch(label, cfg_1, cfg_2, dfg_1, dfg_2, fea_1, fea_2, num_1, num_2, max_num):

    y = np.reshape(label, [B, 1])

    v_num_1 = []
    v_num_2 = []
    for i in range(B):
        v_num_1.append([int(num_1[i])])
        v_num_2.append([int(num_2[i])])

    cfgs_1 = np.empty((B, max_num[0], max_num[0]), dtype = np.float32)
    dfgs_1 = np.empty((B, max_num[0], max_num[0]), dtype = np.float32)
    cfgs_2 = np.empty((B, max_num[0], max_num[0]), dtype = np.float32)
    dfgs_2 = np.empty((B, max_num[0], max_num[0]), dtype = np.float32)
    for i in range(B):
        cfg_arr = np.array(cfg_1[i].decode('utf-8').split(','), dtype = np.float32)
        cfg_adj = np.reshape(cfg_arr, (int(num_1[i]), int(num_1[i])))
        pad_size = int(max_num[i]) - int(num_1[i])
        cfg_adj = np.pad(cfg_adj, ((0, pad_size), (0, pad_size)), \
                    mode = 'constant', constant_values = (0, 0))
        # cfgs_1.append(cfg_adj.tolist())
        # print('=======================================================')
        # print(cfg_adj.shape)
        # print(type(cfg_adj))
        # print(cfg_adj)
        # print('******************************************************')
        # print(type(cfgs_1))
        # print(cfgs_1[i].shape)
        # print(cfgs_1[i])
        # print('=======================================================')
        cfgs_1[i] = cfg_adj
        
        dfg_arr = np.array(dfg_1[i].decode('utf-8').split(','), dtype = np.float32)
        dfg_adj = np.reshape(dfg_arr, (int(num_1[i]), int(num_1[i])))
        dfg_adj = np.pad(dfg_adj, ((0, pad_size), (0, pad_size)), \
                    mode = 'constant', constant_values = (0, 0))
        # dfgs_1.append(dfg_adj.tolist())
        dfgs_1[i] = dfg_adj

        cfg_arr = np.array(cfg_2[i].decode('utf-8').split(','), dtype = np.float32)
        cfg_adj = np.reshape(cfg_arr, (int(num_2[i]), int(num_2[i])))
        pad_size = int(max_num[i]) - int(num_2[i])
        cfg_adj = np.pad(cfg_adj, ((0, pad_size), (0, pad_size)), \
                    mode = 'constant', constant_values = (0, 0))
        # cfgs_2.append(cfg_adj.tolist())
        cfgs_2[i] = cfg_adj

        dfg_arr = np.array(dfg_2[i].decode('utf-8').split(','), dtype = np.float32)
        dfg_adj = np.reshape(dfg_arr, (int(num_2[i]), int(num_2[i])))
        dfg_adj = np.pad(dfg_adj, ((0, pad_size), (0, pad_size)), \
                    mode = 'constant', constant_values = (0, 0))
        # dfgs_2.append(dfg_adj.tolist())
        dfgs_2[i] = dfg_adj

   
   
    feature_1 = np.empty((B, max_num[0], D), dtype = np.float32)
    feature_2 = np.empty((B, max_num[0], D), dtype = np.float32)
    for i in range(B):
        feature_arr = np.array(fea_1[i].decode('utf-8').split(','), dtype=np.float32)
        feature_ori = np.reshape(feature_arr, (-1, D))
        row_pad_size = int(max_num[i]) - int(num_1[i])
        feature_vec1 = np.pad(feature_ori, ((0, row_pad_size), (0, 0)), \
                    mode = 'constant', constant_values = (0, 0))
        # feature_1.append(feature_vec1.tolist())
        feature_1[i] = feature_vec1

        feature_arr = np.array(fea_2[i].decode('utf-8').split(','), dtype=np.float32)
        feature_ori= np.reshape(feature_arr, (-1, D))
        row_pad_size = int(max_num[i]) - int(num_2[i])
        feature_vec2 = np.pad(feature_ori, ((0, row_pad_size), (0, 0)), \
                    mode = 'constant', constant_values = (0, 0))
        # feature_2.append(feature_vec2.tolist())
        feature_2[i] = feature_vec2

    cfgs_1 = adj_to_bias(cfgs_1, max_num, 1)
    dfgs_1 = adj_to_bias(dfgs_1, max_num, 1)
    cfgs_2 = adj_to_bias(cfgs_2, max_num, 1)
    dfgs_2 = adj_to_bias(dfgs_2, max_num, 1)
    return y, cfgs_1, dfgs_1, cfgs_2, dfgs_2, feature_1, feature_2, v_num_1, v_num_2
    # return y, cdfg_1, cdfg_2, feature_1, feature_2, v_num_1, v_num_2

def read_and_decode(filename):
    if filename is not list:
        filename = [filename]
    filename_queue = tf.train.string_input_producer(filename)
    reader = tf.TFRecordReader()
    _, serialized_example = reader.read(filename_queue)
    features = tf.parse_single_example(serialized_example, features = {
        'label': tf.FixedLenFeature([], tf.int64),
        'cfg_1': tf.FixedLenFeature([], tf.string),
        'cfg_2': tf.FixedLenFeature([], tf.string),
        'dfg_1': tf.FixedLenFeature([], tf.string),
        'dfg_2': tf.FixedLenFeature([], tf.string),
        'fea_1': tf.FixedLenFeature([], tf.string),
        'fea_2': tf.FixedLenFeature([], tf.string),
        'num_1': tf.FixedLenFeature([], tf.int64),
        'num_2': tf.FixedLenFeature([], tf.int64),
        'max': tf.FixedLenFeature([], tf.int64),
        }
    )
    label = tf.cast(features['label'], tf.int32)
    cfg_1 = features['cfg_1']
    cfg_2 = features['cfg_2']
    dfg_1 = features['dfg_1']
    dfg_2 = features['dfg_2']
    fea_1 = features['fea_1']
    fea_2 = features['fea_2']
    num_1 = tf.cast(features['num_1'], tf.int32)
    num_2 = tf.cast(features['num_2'], tf.int32)
    max_num_node = tf.cast(features['max'], tf.int32)
    return label, cfg_1, cfg_2, dfg_1, dfg_2, fea_1, fea_2, num_1, num_2, max_num_node

def inputs(filename, batch_size):
    label, cfg_1, cfg_2, dfg_1, dfg_2, fea_1, fea_2, num_1, num_2, \
        max_num_node = read_and_decode(filename)
    b_label, b_cfg_1, b_cfg_2, b_dfg_1, b_dfg_2, b_fea_1, b_fea_2, \
        b_num_1, b_num_2, b_max_num_node = tf.train.shuffle_batch( \
            [label, cfg_1, cfg_2, dfg_1, dfg_2, fea_1, fea_2, num_1, num_2, max_num_node], \
            batch_size = B, capacity = 200, min_after_dequeue = 50,
        )
    return b_label, b_cfg_1, b_cfg_2, b_dfg_1, b_dfg_2, b_fea_1, b_fea_2, \
                                b_num_1, b_num_2, b_max_num_node


def structure2vec(mu_prev, adj_matrix, x, name="structure2vec"):
    with tf.variable_scope(name):
        W_1 = tf.get_variable('W_1', [D, P], tf.float32, \
                        tf.truncated_normal_initializer(mean=0.0, stddev=0.1))
        P_1 = tf.get_variable('P_1', [P, P], tf.float32, \
                        tf.truncated_normal_initializer(mean=0.0, stddev=0.1))
        P_2 = tf.get_variable('P_2', [P, P], tf.float32, \
                        tf.truncated_normal_initializer(mean=0.0, stddev=0.1))
        L = tf.reshape(tf.matmul(adj_matrix, mu_prev, transpose_a=True), (-1, P))  # v_num * P
        S = tf.reshape(tf.matmul(tf.nn.relu(tf.matmul(L, P_2)), P_1), (-1, P))

        return tf.tanh(tf.add(tf.reshape(tf.matmul(tf.reshape(x, (-1, D)), W_1), (-1, P)), S))


def structure2vec_net(adj_matrix, x, v_num):
    with tf.variable_scope("structure2vec_net") as structure2vec_net:
        B_mu_T = tf.Variable(tf.zeros(shape = [0, P]), trainable=False)
        w_2 = tf.get_variable('w_2', [P, P], tf.float32, \
                    tf.truncated_normal_initializer(mean=0.0, stddev=0.1))
        for i in range(B):
            cur_size = tf.to_int32(v_num[i][0])
            mu_0 = tf.reshape(tf.zeros(shape = [2*cur_size, P]),(2*cur_size,P))
            adj = tf.slice(adj_matrix[i], [0,0], [2*cur_size, 2*cur_size])
            fea = tf.slice(x[i],[0,0], [2*cur_size,D])
            mu_1 = structure2vec(mu_0, adj, fea)  # , name = 'mu_1')
            structure2vec_net.reuse_variables()
            for i in range(1, T):
                mu_T = structure2vec(mu_1, adj, fea)  # , name = 'mu_2')

            B_mu_T = tf.concat([B_mu_T,tf.matmul(tf.reshape(tf.reduce_sum(mu_T, 0), (1, P)), w_2)],0)

        return B_mu_T

def attn_head(seq, out_sz, bias_mat, activation, in_drop=0.0, coef_drop=0.0, residual=False):
    with tf.name_scope('my_attn'):
        if in_drop != 0.0:
            seq = tf.nn.dropout(seq, 1.0 - in_drop)

        seq_fts = tf.layers.conv1d(seq, out_sz, 1, use_bias=False)

        # simplest self-attention possible
        f_1 = tf.layers.conv1d(seq_fts, 1, 1)
        f_2 = tf.layers.conv1d(seq_fts, 1, 1)
        logits = f_1 + tf.transpose(f_2, [0, 2, 1])
        coefs = tf.nn.softmax(tf.nn.leaky_relu(logits) + bias_mat)

        if coef_drop != 0.0:
            coefs = tf.nn.dropout(coefs, 1.0 - coef_drop)
        if in_drop != 0.0:
            seq_fts = tf.nn.dropout(seq_fts, 1.0 - in_drop)

        vals = tf.matmul(coefs, seq_fts)
        ret = tf.contrib.layers.bias_add(vals)

        # residual connection
        if residual:
            if seq.shape[-1] != ret.shape[-1]:
                ret = ret + conv1d(seq, ret.shape[-1], 1) # activation
            else:
                ret = ret + seq

        return activation(ret)  # activation


def inference(inputs, nb_classes, nb_nodes, training, attn_drop, ffd_drop, \
        bias_mat, hid_units, n_heads, activation=tf.nn.elu, residual=False):
    attns = []
    for _ in range(n_heads[0]):
        attns.append(attn_head(inputs, bias_mat=bias_mat, \
            out_sz=hid_units[0], activation=activation, \
            in_drop=ffd_drop, coef_drop=attn_drop, residual=False))
    h_1 = tf.concat(attns, axis=-1)
    for i in range(1, len(hid_units)):
        h_old = h_1
        attns = []
        for _ in range(n_heads[i]):
            attns.append(attn_head(h_1, bias_mat=bias_mat, \
                out_sz=hid_units[i], activation=activation, \
                in_drop=ffd_drop, coef_drop=attn_drop, residual=residual))
        h_1 = tf.concat(attns, axis=-1)
    out = []
    for i in range(n_heads[-1]):
        out.append(attn_head(h_1, bias_mat=bias_mat, \
            out_sz=nb_classes, activation=lambda x: x, \
            in_drop=ffd_drop, coef_drop=attn_drop, residual=False))
    logits = tf.add_n(out) / n_heads[-1]
    logits = tf.reduce_sum(logits, 1)

    return logits


def gat2vec_net(cfg_bias, dfg_bias, feats, v_num):
    cfg_bias = cfg_bias + dfg_bias
    with tf.variable_scope("gat2vec_net") as gat2vec_net:
        logits_cfg = inference(feats, P, v_num[0], True, 0, 0, cfg_bias, hid_units, n_heads)
        return logits_cfg
        # tf.get_variable_scope().reuse_variables()
        # gat2vec_net.reuse_variables()
        # logits_dfg = inference(feats, P, v_num[0], True, 0, 0, dfg_bias, [10, 10, 10, 10], [5, 5, 5, 5, 1])
        # logits = logits_cfg + logits_dfg


def calculate_auc(labels, predicts):
    fpr, tpr, thresholds = roc_curve(labels, predicts, pos_label=1)
    AUC = auc(fpr, tpr)
    logging.info("auc : {}".format(AUC))
    return AUC


def contrastive_loss(labels, distance):
    #    tmp= y * tf.square(d)
    #    #tmp= tf.mul(y,tf.square(d))
    #    tmp2 = (1-y) * tf.square(tf.maximum((1 - d),0))
    #    return tf.reduce_sum(tmp +tmp2)/B/2
    #    print "contrastive_loss", y,
    loss = tf.to_float(tf.reduce_sum(tf.square(distance - labels)))
    return loss


def compute_accuracy(prediction, labels):
    accu = 0.0
    threshold = 0.5
    for i in range(len(prediction)):
        if labels[i][0] == 1:
            if prediction[i][0] > threshold:
                accu += 1.0
        else:
            if prediction[i][0] < threshold:
                accu += 1.0
    acc = accu / len(prediction)
    return acc

def cal_distance(model1, model2):
    a_b = tf.reduce_sum(tf.reshape(tf.reduce_prod(tf.concat([tf.reshape(model1,(1,-1)),tf.reshape(model2,(1,-1))],0),0),(B,P)),1,keep_dims=True)
    a_norm = tf.sqrt(tf.reduce_sum(tf.square(model1),1,keep_dims=True))
    b_norm = tf.sqrt(tf.reduce_sum(tf.square(model2),1,keep_dims=True))
    distance = a_b/tf.reshape(tf.reduce_prod(tf.concat([tf.reshape(a_norm,(1,-1)), tf.reshape(b_norm,(1,-1))],0),0),(B,1))
    return distance

# construct the network
# Initializing the variables
# Siamese network major part
# Initializing the variables

init = tf.global_variables_initializer()
global_step = tf.Variable(0, trainable=False)
learning_rate = tf.train.exponential_decay(lr, global_step, decay_steps, decay_rate, staircase=True)

v_num_left = tf.placeholder(tf.float32, shape=[B, 1], name='v_num_left')
cfgs_left = tf.placeholder(tf.float32, shape=([B, None, None]), name='cfgs_left')
dfgs_left = tf.placeholder(tf.float32, shape=([B, None, None]), name='dfgs_left')
feature_left = tf.placeholder(tf.float32, shape=([B, None, D]), name='feature_left')

v_num_right = tf.placeholder(tf.float32, shape=[B, 1], name='v_num_right')
cfgs_right = tf.placeholder(tf.float32, shape=([B, None, None]), name='cfgs_right')
dfgs_right = tf.placeholder(tf.float32, shape=([B, None, None]), name='dfgs_right')
feature_right = tf.placeholder(tf.float32, shape=([B, None, D]), name='feature_right')

labels = tf.placeholder(tf.float32, shape=([B, 1]), name='gt')

dropout_f = tf.placeholder("float")

# with tf.variable_scope("siamese") as siamese:
#     model1 = structure2vec_net(cfgs_left, dfgs_left, feature_left, v_num_left)
#     siamese.reuse_variables()
#     model2 = structure2vec_net(cfgs_right, dfgs_right, feature_right, v_num_right)
with tf.variable_scope("siamese") as siamese:
    model1 = gat2vec_net(cfgs_left, dfgs_left, feature_left, v_num_left)
    siamese.reuse_variables()
    model2 = gat2vec_net(cfgs_right, dfgs_right, feature_right, v_num_right)

dis = cal_distance(model1, model2)
loss = contrastive_loss(labels, dis)

optimizer = tf.train.AdamOptimizer(learning_rate=learning_rate).minimize(loss)

init_opt = tf.global_variables_initializer()
saver = tf.train.Saver()

gpu_options = tf.GPUOptions(allow_growth=True)
tf_config = tf.ConfigProto(allow_soft_placement=True, gpu_options=gpu_options)


batch_train = inputs(config.TFRECORD_TRAIN, B)
batch_valid = inputs(config.TFRECORD_VALID, B)
batch_test = inputs(config.TFRECORD_TEST, B)

statis_train_batch_loss = []
statis_train_batch_acc = []
statis_train_epoch_loss = []
statis_train_epoch_acc = []

statis_valid_batch_loss = []
statis_valid_epoch_loss = []
statis_valid_batch_acc = []
statis_valid_epoch_acc = []
statis_valid_epoch_auc = []

statis_valid_best_labels = []
statis_valid_best_predicts = []
statis_valid_best_auc = []

statis_test_labels = []
statis_test_predicts = []
statis_test_batch_acc = []
statis_test_epoch_acc = []
statis_test_epoch_auc = []

statis_time_get_best_model = []

with tf.Session(config = tf_config) as sess:
# with tf.Session() as sess:
    writer = tf.summary.FileWriter('logs/', sess.graph)
    sess.run(init_opt)
    coord = tf.train.Coordinator()
    threads = tf.train.start_queue_runners(sess=sess, coord=coord)

    best_auc = 0.0 
    time_start = time.time()

    for epoch in tqdm(range(num_epoch)):

        avg_loss = 0.
        avg_acc = 0.
        epoch_avg_loss = 0.
        epoch_avg_acc = 0.
        num_iter = int(train_num / B)
        for i in tqdm(range(num_iter)):
            true_batch_train = sess.run(list(batch_train))
            y, cfgs_1, dfgs_1, cfgs_2, dfgs_2, feature_1, feature_2, v_num_1, v_num_2 \
                = get_batch(*true_batch_train)
            # logging.info('y: {}'.format(y))
            _, loss_value, predict = sess.run([optimizer, loss, dis], feed_dict = { \
                cfgs_left:cfgs_1,dfgs_left:dfgs_1,feature_left:feature_1,v_num_left:v_num_1,\
                cfgs_right:cfgs_2,dfgs_right:dfgs_2,feature_right:feature_2,v_num_right:v_num_2,\
                labels: y, dropout_f: 0.9})
            tr_acc = compute_accuracy(predict, y)

            statis_train_batch_loss.append(loss_value)
            statis_train_batch_acc.append(tr_acc)

            avg_loss += loss_value
            avg_acc += tr_acc
            epoch_avg_loss += loss_value
            epoch_avg_acc += tr_acc

            if (i + 1) % display_step == 0 or i == 0:
                if i > 0:
                    avg_loss /= display_step
                    avg_acc /= display_step
                msg = 'iter: {}, avg_loss: {}, avg_acc: {}'
                logging.info(msg.format(i + 1, avg_loss, avg_acc))
                avg_loss = 0
                avg_acc = 0
        statis_train_epoch_loss.append(epoch_avg_loss / num_iter)
        statis_train_epoch_acc.append(epoch_avg_acc / num_iter)

        if epoch % snapshot == 0:
            total_labels = []
            total_predicts = []
            avg_loss = 0.
            avg_acc = 0.
            valid_start_time = time.time()
            for i in tqdm(range(int(valid_num / B))):
                true_batch_valid = sess.run(list(batch_valid))
                y, cfgs_1, dfgs_1, cfgs_2, dfgs_2, feature_1, feature_2, v_num_1, v_num_2 \
                    = get_batch(*true_batch_valid)
                predict = dis.eval(feed_dict={cfgs_left:cfgs_1,dfgs_left:dfgs_1, \
                    feature_left: feature_1, v_num_left: v_num_1, \
                    cfgs_right: cfgs_2, dfgs_right: dfgs_2, feature_right: feature_2, \
                    v_num_right: v_num_2, labels: y, dropout_f: 0.9})
                valid_acc = compute_accuracy(predict, y)
                valid_loss = loss.eval(feed_dict={labels: y, dis: predict})
                avg_loss += valid_loss
                avg_acc += valid_acc

                statis_valid_batch_loss.append(valid_loss)
                statis_valid_batch_acc.append(valid_acc)

                total_labels.append(y)
                total_predicts.append(predict)
            duration = time.time() - valid_start_time
            avg_loss = avg_loss / (int(valid_num / B))
            avg_acc = avg_acc / (int(valid_num / B))

            statis_valid_epoch_loss.append(avg_loss)
            statis_valid_epoch_acc.append(avg_acc)

            total_labels = np.reshape(total_labels, (-1))
            total_predicts = np.reshape(total_predicts, (-1))
            total_auc = calculate_auc(total_labels, total_predicts)

            statis_valid_epoch_auc.append(total_auc)

            msg = 'epoch: {}, valid time: {}, avg_loss: {}, avg_acc: {}, total_auc: {}'
            logging.info(msg.format(epoch, duration, avg_loss, avg_acc, total_auc))
            if total_auc > best_auc:
                statis_time_get_best_model = [time.time() - time_start]
                statis_valid_best_labels = total_labels
                statis_valid_best_predicts = total_predicts
                statis_valid_best_auc = [total_auc]
                saver.save(sess, os.path.join(config.MODEL_DIR, \
                        "Focus" + config.FILENAME_PREFIX+"_" + \
                        'epoch' + str(epoch) + '_' + \
                        'acc' + str(avg_acc) + '_' + \
                        'auc' + str(total_auc) + ".ckpt"))
                best_auc = total_auc

    avg_loss = 0.
    avg_acc = 0.
    test_total_batch = int(test_num / B)
    start_time = time.time()
    for i in range(test_total_batch):
        true_batch_test = sess.run(list(batch_test))
        y, cfgs_1, dfgs_1, cfgs_2, dfgs_2, feature_1, feature_2, v_num_1, v_num_2 \
            = get_batch(*true_batch_test)
        predict = dis.eval(feed_dict={cfgs_left:cfgs_1,dfgs_left:dfgs_1, \
            feature_left: feature_1, v_num_left: v_num_1, \
            cfgs_right: cfgs_2, dfgs_right: dfgs_2, feature_right: feature_2, \
            v_num_right: v_num_2, labels: y, dropout_f: 1.0})
        # y, graph_1, graph_2, feature_1, feature_2, v_num_1, v_num_2 \
        #     = get_batch(*true_batch_test)
        # predict = dis.eval(feed_dict={graph_left: graph_1, feature_left: feature_1, \
        #     v_num_left: v_num_1, graph_right: graph_2, feature_right: feature_2, \
        #     v_num_right: v_num_2, labels: y, dropout_f: 1.0})
        test_acc = compute_accuracy(predict, y)
        avg_loss += loss.eval(feed_dict={labels: y, dis: predict})
        avg_acc += test_acc

        statis_test_labels.append(y)
        statis_test_predicts.append(predict)
        statis_test_batch_acc.append(test_acc)

    duration = time.time() - start_time
    avg_loss = avg_loss / test_total_batch
    avg_acc = avg_acc / test_total_batch
    statis_test_epoch_acc.append(avg_acc)


    statis_test_labels = np.reshape(statis_test_labels, (-1))
    statis_test_predicts = np.reshape(statis_test_predicts, (-1))
    total_auc = calculate_auc(statis_test_labels, statis_test_predicts)

    statis_test_epoch_auc.append(total_auc)

    logging.info('test time: {}, avg_acc: {}, total_auc: {}'.format(duration, avg_acc,total_auc))
    saver.save(sess, os.path.join(config.MODEL_DIR, \
                        'Focus' + config.FILENAME_PREFIX + '_' + \
                        'epoch' + str(num_epoch) + '_' + \
                        'acc' + str(avg_acc) + '_' + \
                        'auc' + str(total_auc) + '_final.ckpt'))

    coord.request_stop()
    coord.join(threads)

statis_save_file = os.path.join(config.STATIS_DIR, args.exp_name,
                        'Focus' + config.FILENAME_PREFIX + '_' + \
                        'epoch' + str(num_epoch) + '_' + \
                        'D' + str(D) + '_' + \
                        'T' + str(T) + '_' + \
                        'H' + str(H) + '_' + \
                        'P' + str(P) + '.csv')

statis_contents = {}
statis_contents['train_batch_loss'] = statis_train_batch_loss
statis_contents['train_batch_acc'] = statis_train_batch_acc
statis_contents['train_epoch_loss'] = statis_train_epoch_loss
statis_contents['train_epoch_acc'] = statis_train_epoch_acc

statis_contents['valid_batch_loss'] = statis_valid_batch_loss
statis_contents['valid_epoch_loss'] = statis_valid_epoch_loss
statis_contents['valid_batch_acc'] = statis_valid_batch_acc
statis_contents['valid_epoch_acc'] = statis_valid_epoch_acc
statis_contents['valid_epoch_auc'] = statis_valid_epoch_auc

statis_contents['valid_best_labels'] = statis_valid_best_labels
statis_contents['valid_best_predicts'] = statis_valid_best_predicts
statis_contents['valid_best_auc'] = statis_valid_best_auc

statis_contents['test_labels'] = statis_test_labels
statis_contents['test_predicts'] = statis_test_predicts
statis_contents['test_batch_acc'] = statis_test_batch_acc
statis_contents['test_epoch_acc'] = statis_test_epoch_acc
statis_contents['test_epoch_auc'] = statis_test_epoch_auc

statis_contents['time_get_best_model'] = statis_time_get_best_model

statis_contents['train_epoch'] = [num_epoch]
statis_contents['batch_size'] = [B]
statis_contents['D'] = [D]
statis_contents['T'] = [T]
statis_contents['H'] = [H]
statis_contents['P'] = [P]
statis_contents['hide_units'] = hid_units
statis_contents['n_heads'] = n_heads

save_dict_to_csv(statis_save_file, statis_contents)
