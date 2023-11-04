import argparse
import key_store
import logging
import sys
import uuid

def list_keys(args):
    keystore = key_store.FSKeyStore.open(args.keystore)
    for key in keystore.all_keys:
        flags = "" if key.is_valid else "bad_sum"
        print("%s [%s]" % (key.name, flags))

def report(args):
    from datetime import datetime
    import os
    import report

    keystore = key_store.FSKeyStore.open(args.keystore)
    report_name = datetime.today().strftime('keys_%Y%m%dT%H%M%S.pdf')
    report_path = os.path.join(args.keystore, report_name)
    report.generate_key_store_report(report_path, keystore)
    print("report generated at: %s" % report_path)

def backup(args):
    keystore = key_store.FSKeyStore.open(args.keystore)
    dest_keystore = key_store.FSKeyStore.create_or_open(args.dest)

    copy_pairs = [(key, dest_keystore.get_key_unchecked(key.name)) for key in keystore.all_keys]
    if not args.force:
        valid_keys = list(filter(lambda pair: pair[1].is_valid, copy_pairs))
        if valid_keys:
            print("not backing up because the following keys already exist in destination")
            for (src, dst) in valid_keys:
                print(dst.name)
            sys.exit(1)

    for (src, dst) in copy_pairs:
        src.copy(dst)
    

def make_zfs_key(keystore: key_store.FSKeyStore, dataset: str):
    key_name = uuid.uuid4().hex
    secret = key_store.Secret.generate(len=32)
    key = keystore.add_key(key_name, secret, extra_params={"zfs_dataset": dataset})
    if key is not None:
        return key.abs_path
    else:
        return None

def zfs_rekey(args):
    import zfs

    datasets_to_rekey = zfs.get_local_encrypted_datasets(args.datasets, args.recursive)
    if args.keystore == "-":
        for dataset in datasets_to_rekey:
            print("would rekey: %s" % dataset)
    else:
        keystore = key_store.FSKeyStore.open(args.keystore)
        for dataset in datasets_to_rekey:
            key_path = make_zfs_key(keystore, dataset)
            logging.info("rekeying: %s -> %s", dataset, key_path)
            zfs.set_dataset_key(dataset, key_path)

def zfs_create(args):
    import zfs

    keystore = key_store.FSKeyStore.create_or_open(args.keystore)
    key_path = make_zfs_key(keystore, args.dataset)
    logging.info("creating encrypted dataset: %s -> %s", args.dataset, key_path)
    zfs.make_encrypted_dataset(args.dataset, key_path, args.options)

def zfs_list(args):
    import key_store
    import zfs

def main():
    apps = {
        'list': list_keys,
        'report': report,
        'backup': backup,
        'zfs_rekey': zfs_rekey,
        'zfs_create': zfs_create,
    }

    parser = argparse.ArgumentParser(prog='key_store', description="Tools for interacting with a key store")

    subparsers = parser.add_subparsers(help="commands", dest='command')

    list_parser = subparsers.add_parser('list', help="List keys stored in the store")
    list_parser.add_argument('keystore', help="path of a keystore to list keys from")

    report_parser = subparsers.add_parser('report', help="Generate a printable pdf of the keys")
    report_parser.add_argument('keystore', help="path of a keystore to generate the pdf from")

    backup_parser = subparsers.add_parser('backup', help="Backup one keystore to another")
    backup_parser.add_argument('keystore', help="path of keystore to backup")
    backup_parser.add_argument('dest', help="path of keystore to backup to")
    backup_parser.add_argument('-f', '--force', action='store_true', help="backup even if a key with the same name exists in the destination keystore")

    zfs_rekey_parser = subparsers.add_parser('zfs_rekey', help="Generate new keys for datasets in zfs")
    zfs_rekey_parser.add_argument('keystore', help="path of a keystore to store the new keys in, '-' to do a dry run")
    zfs_rekey_parser.add_argument('datasets', metavar="dataset", nargs='*', help='list of datasets to rekey, if none are passed all datasets are selected')
    zfs_rekey_parser.add_argument('-r', '--recursive', action='store_true', help='rekey all child datasets of the selected datasets')

    zfs_create_parser = subparsers.add_parser('zfs_create', help="Create a new dataset encrypted with a key in the keystore")
    zfs_create_parser.add_argument('keystore', help="path of a keystore to create the new key in")
    zfs_create_parser.add_argument('dataset', help="dataset to create")
    zfs_create_parser.add_argument('options', metavar='option', nargs='*', help="extra 'zfs create' options to add when creating")

    zfs_list_parser = subparsers.add_parser('zfs_list', help="List zfs datasets that are keyed through the keystore")
    zfs_list_parser.add_argument('keystore', help="path of the keystore to list datasets for")

    args = parser.parse_args()
    apps[args.command](args)

if __name__ == "__main__":
    log = logging.getLogger()
    log.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    log.addHandler(handler)
    
    main()