#!/usr/bin/python
# -*- coding: UTF-8 -*-

import config
import os
import sys
import subprocess
import glob
import argparse
import threading
import struct

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def checkMachine(path):
    """
    super simple and note exact way to check if 32-bit or 64-bit
    """
    bit64 = ["aarch64", "powerpc64", "x64", "mips64"]
    # TODO 最后一个拼写错误，为了适应我们命名的拼写错误，命名纠正后去掉
    bit32 = ["arm32", "powerpc32", "x86", "mips32", "powepc32"]
    for b in bit64:
        if b in path:
            return 64
    for b in bit32:
        if b in path:
            return 32
    return 0

def endsWith(path, names):
    for name in names:
        if path.endswith(name):
            return True
    return False

def gen_idb_single(dirs, work_dir, bin_dir, feature_dir, force):
    '''
    单线程处理多个目录
    '''
    # 临时文件扩展名
    temp_extension = [".id0", ".id1", ".id2", ".nam", ".til", "id3", ".dmp"]
    output_extension = [".idb", ".i64", ".asm"]
    for d in dirs:
        for file_path in glob.glob(d + os.sep + "*"):
            # remove database/asm file if force
            if endsWith(file_path, output_extension):
                # if force:
                #     os.remove(file_path)
                continue
            # remove existing temp file
            if endsWith(file_path, temp_extension):
                # os.remove(file_path)
                continue

            # analyse
            binary_path = file_path
            database_file = file_path
            machine = checkMachine(binary_path)
            ida_path = "ls"
            if 32 == machine:
                ida_path = "C:\Program Files\IDA 7.0\ida.exe"
                database_file += ".idb"
            elif 64 == machine:
                ida_path = "C:\Program Files\IDA 7.0\ida64.exe"
                database_file += ".i64"
            else:
                print("unknown file type ", binary_path)
                continue
            
            args = [ida_path, "-B", binary_path]
            # print(" ".join(args) + "\n")
            subprocess.call(" ".join(args))
            relpath = os.path.relpath(d, bin_dir)
            python_args = [work_dir + os.sep + "2_gen_features.py", feature_dir + os.sep + relpath, database_file]
            # python_args = [work_dir + os.sep + "2_gen_features.py"]
            process_args = [ida_path, "-A", ("-S\"" + " ".join(python_args) + "\""), binary_path]
            print(" ".join(process_args) + "\n")
            subprocess.call(" ".join(process_args))

def gen_idb_batch(work_dir, bin_dir, feature_dir, force, n_thread = 7):
    '''
    多线程处理多个目录
    '''
    bins = []
    for program in glob.glob(bin_dir + os.sep + "*"):
        for variant in glob.glob(program + os.sep + "*"):
            bins.append(variant)
    batch_size = max(1, int(len(bins) / n_thread))
    threads = []
    for i in range(n_thread):
        t = threading.Thread(target=gen_idb_single, args=(bins[i*batch_size:(i+1)*batch_size], work_dir, bin_dir, feature_dir, force))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def main():
    parser = argparse.ArgumentParser(description='cfg extraction')
    parser.add_argument('-work_dir', '--work_dir',
                        help="work directory path",
                        type=str,
                        default=".")
    parser.add_argument('-binary', '--binary',
                        help="binary input path, default to <work_dir>/binary",
                        type=str,
                        default="")
    parser.add_argument('-feature', '--feature',
                        help="feature path, default to <work_dir>/feature",
                        type=str,
                        default="")
    parser.add_argument("-batch", "--batch",
                        help="batch mode",
                        type=str2bool,
                        default="True")
    parser.add_argument("--force",
                        help="force to generate database files anyway or not(if not, it will skip generating if those file exists)",
                        type=str2bool,
                        default="False")

    args = parser.parse_args()

    work_dir = args.work_dir
    if work_dir == "." or work_dir == "./":
        work_dir = os.getcwd()
    bin_dir = args.binary
    if bin_dir == "":
        bin_dir = work_dir + os.sep + "binary"
    feature_dir = args.feature
    if feature_dir == "":
        feature_dir = work_dir + os.sep + "features"
    batch = args.batch
    force = args.force
    print(bin_dir, batch, force)
    if batch:
        gen_idb_batch(work_dir, bin_dir, feature_dir, force, 8)
    else:
        gen_idb_single(bin_dir, work_dir, bin_dir, feature_dir, force)


if __name__ == "__main__":
    main()