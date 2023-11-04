# File based key storage designed for ZFS

This is a utility to store keys and meta information about keys as files in a filesystem.  When the keys are files you can load them directly with zfs instead of using a separate program to load them.  The idea is that you can have an external non-volatile storage device to store your keys, and multiple backups of those keys.  There is also a utility to generate a pdf from your keystore so you can backup your keystore by printing out your keys.
