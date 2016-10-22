from __future__ import with_statement

import os
import sys
import errno

from fuse import FUSE, FuseOSError, Operations
from functools import wraps
import plyvel
import hashlib


def path_deco(fn):
    @wraps(fn)
    def _impl(self, *args):
        self.path_hash = "file_hash_{}".format(args[0])
        h = self.d.get(args[0][1:].encode('utf8'))
        print("FN: {}\nPATH: {}\nHASH: {}\n".format(fn, args[0], h))
        if h:
            args = list(args)
            args[0] = h
            tuple(args)
            return fn(self, *args)
        else:
            return fn(self, *args)
    return _impl


class Passthrough(Operations):
    def __init__(self, root):
        self.root = root.encode('utf8')
        self.d = plyvel.DB('/tmp/plydb_{}'.format(root),
                           create_if_missing=True)

    # Helpers
    # =======

    def _full_path(self, partial):
        if partial[0] == ("/"):
            partial = partial[1:].encode('utf8')
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
    # ==================

    @path_deco
    def access(self, path, mode):
        # import pdb; pdb.set_trace()
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    @path_deco
    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    @path_deco
    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    @path_deco
    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        print("ST: {}, {}".format(st, type(st)))
        return dict((key, getattr(st, key)) for key in ('st_atime',
                                                        'st_ctime',
                                                        'st_gid',
                                                        'st_mode',
                                                        'st_mtime',
                                                        'st_nlink',
                                                        'st_size',
                                                        'st_uid'))

    @path_deco
    def readdir(self, path, fh):
        full_path = self._full_path(path)
        if full_path == self.root + b"/":
            for k, v in self.d:
                print("key: {}".format(k))
                yield (k.decode('utf8'), 0, 0)

    @path_deco
    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    @path_deco
    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    @path_deco
    def rmdir(self, path):
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    @path_deco
    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    @path_deco
    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail',
                                                         'f_bfree',
                                                         'f_blocks',
                                                         'f_bsize',
                                                         'f_favail',
                                                         'f_ffree',
                                                         'f_files',
                                                         'f_flag',
                                                         'f_frsize',
                                                         'f_namemax'))

    @path_deco
    def unlink(self, path):
        return os.unlink(self._full_path(path))

    @path_deco
    def symlink(self, name, target):
        return os.symlink(name, self._full_path(target))

    @path_deco
    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    @path_deco
    def link(self, target, name):
        return os.link(self._full_path(target), self._full_path(name))

    @path_deco
    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods
    # ============
    @path_deco
    def open(self, path, flags):
        print("OPEN: {}, {}".format(path, flags))
        print("FILE_HASH: {}".format(self.path_hash))
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    @path_deco
    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    @path_deco
    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    @path_deco
    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    @path_deco
    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    @path_deco
    def flush(self, path, fh):
        return os.fsync(fh)

    @path_deco
    def release(self, path, fh):
        return os.close(fh)

    @path_deco
    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


def do_md5(dn, f):
    fr = open(os.path.join(dn, f), 'rb').read()
    return hashlib.md5(fr).hexdigest().encode('utf8')


def hashdb(root):
    d = plyvel.DB('/tmp/plydb_{}'.format(root), create_if_missing=True)
    with d.write_batch(transaction=True) as dw:
        for dn, sdl, fl in os.walk(root):
            for f in fl:
                dw.put(do_md5(dn, f),
                       os.path.join(dn, f).encode('utf8')[len(root)+1:])


def main(mountpoint, root):
    print("MOUNTPOINT: {}\nROOT: {}".format(mountpoint, root))
    hashdb(root)
    print('hashdb')
    FUSE(Passthrough(root), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1])
