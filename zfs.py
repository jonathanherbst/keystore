import argparse
import os
import shutil
import subprocess

def zfs_bin() -> str:
    return shutil.which('zfs')

def get_zfs_encryption_info(datasets, recursive=False):
    flags = "-rH" if recursive else "-H"
    cmd = [zfs_bin(), 'get', flags, 'encryption,keylocation,keyformat'] + list(datasets)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    data, _ = process.communicate()
    if process.returncode:
        return None
    
    info = {}
    for line in data.decode().splitlines():
        dataset, prop, value, default = line.split()
        if dataset not in info:
            info[dataset] = {}
        info[dataset][prop] = value
    return info

def get_local_encrypted_datasets(datasets, recursive=False):
    local_filter = lambda d: d[1]['keylocation'] not in ['-', 'none', '']
    return dict(filter(local_filter, get_zfs_encryption_info(datasets, recursive).items()))

def set_dataset_key(dataset, key_path):
    key_path = os.path.abspath(key_path)
    key_location = 'keylocation=file://%s' % key_path
    cmd = [zfs_bin(), 'change-key', '-o', key_location, '-o', "keyformat=raw", dataset]

    process = subprocess.Popen(cmd)
    return process.wait() == 0

def make_encrypted_dataset(dataset, key_path, options=None):
    key_path = os.path.abspath(key_path)
    encryption = "encryption=aes-256-gcm"
    keylocation = "keylocation=file://%s" % key_path
    keyformat = "keyformat=raw"
    cmd = [zfs_bin(), 'create', '-o', encryption, '-o', keylocation, '-o', keyformat]
    for option in options:
        cmd.extend(('-o', option))
    cmd.append(dataset)

    process = subprocess.Popen(cmd)
    return process.wait() == 0

def rekey():
    arg_parser = argparse.ArgumentParser(prog='zfs_rekey', description='Rekey zfs datasets into a key store')
    arg_parser.add_argument('keystore', help="path of a keystore store the new keys in, '-' to do a dry run")
    arg_parser.add_argument('datasets', metavar="dataset", nargs='*', help='list of datasets to rekey, if none are passed all datasets are selected')
    arg_parser.add_argument('-r', '--recursive', action='store_true', help='rekey all child datasets of the selected datasets')

    args = arg_parser.parse_args()

    datasets_to_rekey = get_local_encrypted_datasets(args.datasets, args.recursive)
    if args.keystore == "-":
        print("DRY RUN, no changes made")

    print("rekeying:")
    for dataset in datasets_to_rekey:
        print("\t" + dataset)

if __name__ == "__main__":
    rekey()