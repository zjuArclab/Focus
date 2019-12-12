import os
import shutil
import glob
root_path = 'D:\\Binary_Similarity\\0_Libs'
remains = set(['busybox', 'libcrypto.so.1.0.0', 'libssl.so.1.0.0', 'openssl'])
files = glob.glob(root_path + os.sep + '\\*\\*\\*')
for file in files:
    h, t = os.path.split(file)
    if t not in remains:
        os.remove(file)


