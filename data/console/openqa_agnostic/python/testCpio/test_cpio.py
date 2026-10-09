# SUSE's openQA tests
#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
"""Functional tests for GNU cpio.

Ported from tests/console/cpio.pm and extended with the upstream GNU cpio
tests/ matrix (copy-in/copy-out, interdir, symlinks and delayed setstat).
The test runs standalone on any system with Python 3.6+, pytest and the cpio
binary installed, and does not depend on openQA variables. The runtest
metadata lists the individual checks.

cpio gained symlink timestamp restoration in 2.15 and the --block-size and
CVE-2015-1197 fixes in 2.13. SLE 15 ships cpio 2.12 (SP2/SP3) and 2.13
(SP4+), so the checks that need a newer behaviour are skipped there instead
of failing the job.
"""

import os
import re
import subprocess

import pytest

# The archive formats exercised by the original console test. cpio still
# accepts all of them; hpbin/hpodc are the HP variants of bin/odc.
FORMATS = ('bin', 'odc', 'newc', 'crc', 'tar', 'ustar', 'hpbin', 'hpodc')

# Commands must never be able to block on a prompt or otherwise hang the job.
RUN_TIMEOUT = 120


def _run(args, cwd=None, text=False, input=None, umask=None):
    """Run a command with a timeout, detached from the controlling terminal.

    :param args list the command and its arguments
    :param cwd str directory to run in, or None to inherit the current one
    :param text bool capture text and merge stderr into stdout, or capture bytes
    :param input bytes or str data to feed on stdin, or None to use /dev/null
    :param umask int umask to apply in the child, or None to inherit it
    :return subprocess.CompletedProcess the finished process
    """
    kwargs = {
        'cwd': cwd,
        'stdout': subprocess.PIPE,
        'stderr': subprocess.STDOUT if text else subprocess.PIPE,
        'universal_newlines': text,
        'timeout': RUN_TIMEOUT,
    }
    if input is None:
        kwargs['stdin'] = subprocess.DEVNULL
    else:
        kwargs['input'] = input
    if umask is not None:
        kwargs['preexec_fn'] = lambda: os.umask(umask)
    return subprocess.run(args, **kwargs)


def run_text(args, cwd=None, input=None, umask=None):
    """Run a command and capture its combined text output.

    stderr is merged into stdout, so the returned .stderr is always None.

    :param args list the command and its arguments
    :param cwd str directory to run in, or None to inherit the current one
    :param input str data to feed on stdin, or None to use /dev/null
    :param umask int umask to apply in the child, or None to inherit it
    :return subprocess.CompletedProcess the finished process with text output
    """
    return _run(args, cwd=cwd, text=True, input=input, umask=umask)


def read_bytes(path):
    """Return the raw contents of a file.

    :param path str path of the file to read
    :return bytes the file contents
    """
    with open(path, 'rb') as handle:
        return handle.read()


def run_bytes(args, cwd=None, input=None):
    """Run a command and capture its raw stdout, keeping stderr separate.

    :param args list the command and its arguments
    :param cwd str directory to run in, or None to inherit the current one
    :param input bytes data to feed on stdin, or None to use /dev/null
    :return subprocess.CompletedProcess the finished process with byte output
    """
    return _run(args, cwd=cwd, text=False, input=input)


def combined(result):
    """Return a process's stdout and stderr concatenated.

    cpio writes diagnostics and verbose listings to stderr, so both streams
    have to be considered when asserting on its messages.

    :param result subprocess.CompletedProcess with byte output
    :return bytes stdout followed by stderr
    """
    return result.stdout + (result.stderr or b'')


def _cpio_version():
    """Return the installed GNU cpio version as a (major, minor) tuple.

    :return tuple of int, or (0, 0) when cpio is missing or unparsable
    """
    try:
        result = _run(['cpio', '--version'])
    except OSError:
        return (0, 0)
    first = result.stdout.decode('utf-8', 'replace').splitlines()[0] if result.stdout else ''
    match = re.search(r'(\d+)\.(\d+)', first)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


CPIO_VERSION = _cpio_version()


def needs_cpio(major, minor):
    """Skip a test when the installed cpio is older than major.minor.

    :param major int required major version
    :param minor int required minor version
    :return pytest.mark object to apply as a decorator
    """
    return pytest.mark.skipif(
        CPIO_VERSION < (major, minor),
        reason='requires cpio >= %d.%d (found %d.%d)' % (major, minor, CPIO_VERSION[0], CPIO_VERSION[1]))


def write_tree(root):
    """Create the deterministic sample tree used by the round-trip tests.

    The tree covers a nested directory, an empty directory, an empty file, a
    filename containing a space, a symlink and a member larger than one cpio
    I/O block.

    :param root str directory the tree is created in
    """
    members = {
        'a.txt': b'hello from the cpio agnostic test\n',
        'empty.txt': b'',
        'with space.txt': b'a filename containing a space\n',
        'nested/b.bin': b'nested block %06d\n' % 0,
        'sub/deep/c.txt': b'deeply nested member\n',
    }
    # A few hundred KiB, so copy-out/copy-in span more than one 512-byte block.
    members['nested/big.bin'] = b''.join(b'cpio agnostic payload %06d\n' % i for i in range(20000))
    for name, content in members.items():
        path = os.path.join(root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as handle:
            handle.write(content)
    os.makedirs(os.path.join(root, 'empty_dir'))
    os.symlink('a.txt', os.path.join(root, 'link'))


def tree_names(root):
    """Return the member names to feed cpio on stdin for the sample tree.

    Directories are listed as well, so copy-out stores their mode instead of
    leaving it to the extraction umask.

    :param root str directory to walk
    :return list of str relative member names, including '.'
    """
    names = ['.']
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            names.append(os.path.relpath(os.path.join(dirpath, name), root))
    return names


def snapshot(root):
    """Return the tree below a directory as a comparable dict.

    :param root str directory to walk
    :return dict mapping relative paths to ('dir', mode), ('link', target) or
            ('file', mode, bytes)
    """
    result = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            path = os.path.join(dirpath, name)
            result[os.path.relpath(path, root)] = ('dir', os.stat(path).st_mode & 0o777)
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if os.path.islink(path):
                result[rel] = ('link', os.readlink(path))
            else:
                result[rel] = ('file', os.stat(path).st_mode & 0o777, read_bytes(path))
    return result


def copyout(cwd, names, fmt=None):
    """Archive the given names from a directory and return the archive path.

    The archive is written next to (not inside) the directory, so a snapshot
    of the source tree stays comparable to the extracted tree.

    :param cwd str directory to archive
    :param names list of str names to pass to cpio on stdin
    :param fmt str cpio format, or None for cpio's default
    :return str path of the written archive
    """
    archive = os.path.abspath(cwd) + '.cpio'
    args = ['cpio', '--quiet', '-o']
    if fmt:
        args += ['-H', fmt]
    result = _run(args, cwd=cwd, input=('\n'.join(names) + '\n').encode())
    assert result.returncode == 0, result.stderr
    with open(archive, 'wb') as handle:
        handle.write(result.stdout)
    return archive


def copyin(archive, out, fmt=None, extra=None, umask=None):
    """Extract an archive into a directory and return the completed process.

    :param archive str path of the archive to extract
    :param out str target directory, created if missing
    :param fmt str cpio format, or None for cpio's default
    :param extra list of extra cpio arguments, or None
    :param umask int umask to apply in the child, or None to inherit it
    :return subprocess.CompletedProcess the finished process
    """
    os.makedirs(out, exist_ok=True)
    args = ['cpio', '--quiet', '-i', '-d']
    if fmt:
        args += ['-H', fmt]
    if extra:
        args += extra
    with open(archive, 'rb') as handle:
        return _run(args, cwd=out, input=handle.read(), umask=umask)


def test_version():
    """cpio reports itself as GNU cpio."""
    result = run_text(['cpio', '--version'])
    assert result.returncode == 0, result.stdout
    assert 'GNU cpio' in result.stdout, result.stdout


@pytest.mark.parametrize('fmt', FORMATS)
def test_roundtrip_all_formats(tmp_path, fmt):
    """Every supported format round-trips content, types and modes."""
    tree = os.path.join(tmp_path, 'tree')
    write_tree(tree)
    archive = copyout(tree, tree_names(tree), fmt=fmt)

    out = os.path.join(tmp_path, 'out')
    result = copyin(archive, out, fmt=fmt)
    assert result.returncode == 0, result.stdout

    assert snapshot(out) == snapshot(tree), 'format %s did not round-trip the tree' % fmt


def test_roundtrip_keeps_mtime(tmp_path):
    """Extraction with -m restores the member modification time."""
    tree = os.path.join(tmp_path, 'tree')
    write_tree(tree)
    stamp = 1500000000
    os.utime(os.path.join(tree, 'a.txt'), (stamp, stamp))
    archive = copyout(tree, tree_names(tree))

    out = os.path.join(tmp_path, 'out')
    result = copyin(archive, out, extra=['-m'])
    assert result.returncode == 0, result.stdout
    assert int(os.stat(os.path.join(out, 'a.txt')).st_mtime) == stamp


def test_archive_file_options(tmp_path):
    """-O and -I read and write the archive through a named file."""
    tree = os.path.join(tmp_path, 'tree')
    write_tree(tree)
    archive = os.path.join(tmp_path, 'named.cpio')
    names = tree_names(tree)
    result = _run(['cpio', '--quiet', '-o', '-O', archive], cwd=tree,
        input=('\n'.join(names) + '\n').encode())
    assert result.returncode == 0, result.stderr

    out = os.path.join(tmp_path, 'out')
    os.makedirs(out)
    result = _run(['cpio', '--quiet', '-i', '-d', '-I', archive], cwd=out)
    assert result.returncode == 0, result.stderr
    assert snapshot(out) == snapshot(tree)


def test_missing_member_does_not_hang(tmp_path):
    """An empty archive with a file list must fail, not hang.

    Regression check for bsc#1189463, where a cpio call hung all build
    workers. The member named in -E does not exist in the empty input, and
    cpio reports the unreadable tape instead of blocking.
    """
    with open(os.path.join(tmp_path, 'filelist'), 'w') as handle:
        handle.write('1234\n')
    # run_text feeds /dev/null on stdin, so no archive can be read.
    result = run_text(['cpio', '-i', '-d', '-v', '-E', 'filelist'], cwd=str(tmp_path))
    assert result.returncode != 0, result.stdout
    assert 'ioctl' in result.stdout, result.stdout


def test_symlink_roundtrip(tmp_path):
    """A symlink is stored as a symlink and restored unchanged."""
    tree = os.path.join(tmp_path, 'tree')
    os.makedirs(tree)
    with open(os.path.join(tree, 'file'), 'wb') as handle:
        handle.write(b'target contents\n')
    os.symlink('file', os.path.join(tree, 'symlink'))
    # An absolute link exercises the non-dangling case too.
    os.symlink(os.path.join(tree, 'file'), os.path.join(tree, 'absolute'))
    archive = copyout(tree, ['file', 'symlink', 'absolute'])

    out = os.path.join(tmp_path, 'out')
    result = copyin(archive, out)
    assert result.returncode == 0, result.stdout
    assert os.path.islink(os.path.join(out, 'symlink'))
    assert os.readlink(os.path.join(out, 'symlink')) == 'file'
    assert os.path.islink(os.path.join(out, 'absolute')), 'absolute symlink was dereferenced'
    assert read_bytes(os.path.join(out, 'symlink')) == b'target contents\n'


def test_symlink_long_target(tmp_path):
    """A symlink whose target exceeds the read buffer keeps its full target."""
    tree = os.path.join(tmp_path, 'tree')
    # 52 levels of 'xxxxxxxxx/' is longer than cpio's old READBUFSIZE.
    target = '/'.join(['xxxxxxxxx'] * 52)
    os.makedirs(os.path.join(tree, target))
    os.symlink(target, os.path.join(tree, 'x'))
    archive = copyout(tree, ['x'])

    # The archive is binary, the listing is text, so read bytes and decode.
    listing = run_bytes(['cpio', '-tv'], input=read_bytes(archive))
    assert listing.returncode == 0, listing.stdout
    text = listing.stdout.decode('utf-8', 'replace')
    match = re.search(r'->\s*(\S+)\s*$', text, re.MULTILINE)
    assert match, text
    assert match.group(1) == target, match.group(1)


def test_symlink_to_stdout(tmp_path):
    """--to-stdout writes the regular member and skips the symlink."""
    tree = os.path.join(tmp_path, 'tree')
    os.makedirs(tree)
    with open(os.path.join(tree, 'file'), 'wb') as handle:
        handle.write(b'stream me\n')
    os.symlink('file', os.path.join(tree, 'symlink'))
    archive = copyout(tree, ['file', 'symlink'])

    result = run_bytes(['cpio', '--quiet', '--to-stdout', '-i'], input=read_bytes(archive))
    assert result.returncode == 0, result.stdout
    assert result.stdout == b'stream me\n', result.stdout


def test_hardlink_preserved(tmp_path):
    """newc extraction recreates a hardlink as the same inode."""
    tree = os.path.join(tmp_path, 'tree')
    os.makedirs(tree)
    with open(os.path.join(tree, 'f1'), 'wb') as handle:
        handle.write(b'hardlinked\n')
    os.link(os.path.join(tree, 'f1'), os.path.join(tree, 'f2'))
    archive = copyout(tree, ['f1', 'f2'], fmt='newc')

    out = os.path.join(tmp_path, 'out')
    result = copyin(archive, out, fmt='newc')
    assert result.returncode == 0, result.stdout
    stat1 = os.stat(os.path.join(out, 'f1'))
    stat2 = os.stat(os.path.join(out, 'f2'))
    assert stat1.st_ino == stat2.st_ino, 'hardlink not preserved'
    assert stat1.st_nlink == 2, stat1.st_nlink
    assert read_bytes(os.path.join(out, 'f2')) == b'hardlinked\n'


@needs_cpio(2, 13)
def test_no_absolute_filenames_symlink(tmp_path):
    """--no-absolute-filenames must not restore an absolute symlink.

    From the upstream CVE-2015-1197 test (fixed in cpio 2.13): a symlink to an
    absolute directory followed by a file below it must not let the file
    escape through the restored link; cpio reports the member and exits 2.
    """
    work = os.path.join(tmp_path, 'work')
    os.makedirs(work)
    target = os.path.join(work, 'tmp')
    os.makedirs(target)
    with open(os.path.join(target, 'file'), 'wb') as handle:
        handle.write(b'payload\n')
    os.symlink(target, os.path.join(work, 'dir'))
    archive = copyout(work, ['dir', 'dir/file'])
    # Remove the source tree, exactly as the upstream test does, so a restored
    # absolute symlink would point at a real directory and expose the file.
    os.remove(os.path.join(target, 'file'))
    os.rmdir(target)
    os.unlink(os.path.join(work, 'dir'))

    out = os.path.join(tmp_path, 'out')
    result = copyin(archive, out, extra=['--no-absolute-filenames', '-v'])
    assert result.returncode == 2, combined(result)
    assert b'Cannot open: Not a directory' in combined(result), combined(result)
    # The security property: nothing may be written back to the target.
    assert not os.path.exists(os.path.join(work, 'tmp', 'file')), 'payload escaped the extraction'


def test_preserve_directory_mode(tmp_path):
    """A directory with mode 0500 is extracted with that mode.

    From upstream setstat01: cpio up to 2.10 set the mode on creation, which
    made a 0500 directory impossible to populate.
    """
    tree = os.path.join(tmp_path, 'tree')
    os.makedirs(os.path.join(tree, 'dir'))
    with open(os.path.join(tree, 'dir', 'file'), 'wb') as handle:
        handle.write(b'test file\n')
    os.chmod(os.path.join(tree, 'dir'), 0o500)
    archive = copyout(tree, ['dir', 'dir/file'])

    out = os.path.join(tmp_path, 'out')
    try:
        result = copyin(archive, out)
        assert result.returncode == 0, result.stdout
        assert os.stat(os.path.join(out, 'dir')).st_mode & 0o777 == 0o500
        assert read_bytes(os.path.join(out, 'dir', 'file')) == b'test file\n'
    finally:
        # A 0500 directory has no write bit, so pytest could not remove its
        # own temporary tree afterwards.
        for base in (os.path.join(tree, 'dir'), os.path.join(out, 'dir')):
            if os.path.isdir(base):
                os.chmod(base, 0o700)


def test_setstat_umask_ignored(tmp_path):
    """The extraction umask must not mask the archived mode.

    From upstream setstat04: a directory archived as 0755 must stay 0755, and
    its file 0644, even when extraction runs under umask 077.
    """
    tree = os.path.join(tmp_path, 'tree')
    os.makedirs(os.path.join(tree, 'dir'))
    with open(os.path.join(tree, 'dir', 'file'), 'wb') as handle:
        handle.write(b'test file\n')
    os.chmod(os.path.join(tree, 'dir'), 0o755)
    archive = copyout(tree, ['dir', 'dir/file'])

    out = os.path.join(tmp_path, 'out')
    result = copyin(archive, out, umask=0o077)
    assert result.returncode == 0, result.stdout
    assert os.stat(os.path.join(out, 'dir')).st_mode & 0o777 == 0o755
    assert os.stat(os.path.join(out, 'dir', 'file')).st_mode & 0o777 == 0o644


@needs_cpio(2, 15)
def test_symlink_mtime_preserved(tmp_path):
    """-m restores a symlink's own modification time.

    From upstream linktime01; cpio restores symlink times only since 2.15.
    The mtime of the link, not of its target, must survive the round trip.
    """
    tree = os.path.join(tmp_path, 'tree')
    os.makedirs(os.path.join(tree, 'dir'))
    with open(os.path.join(tree, 'dir', 'file1'), 'wb') as handle:
        handle.write(b'x\n')
    link = os.path.join(tree, 'dirlink')
    os.symlink('dir', link)
    stamp = 1500000000
    try:
        os.utime(link, (stamp, stamp), follow_symlinks=False)
    except (NotImplementedError, OSError):
        pytest.skip('filesystem does not support symlink timestamps')
    archive = copyout(tree, ['dir', 'dir/file1', 'dirlink'])

    out = os.path.join(tmp_path, 'out')
    result = copyin(archive, out, extra=['-m'])
    assert result.returncode == 0, result.stdout
    assert int(os.lstat(os.path.join(out, 'dirlink')).st_mtime) == stamp


def test_list_members(tmp_path):
    """cpio -it lists exactly the archived members."""
    tree = os.path.join(tmp_path, 'tree')
    write_tree(tree)
    names = tree_names(tree)
    archive = copyout(tree, names)

    result = run_bytes(['cpio', '--quiet', '-it'], input=read_bytes(archive))
    assert result.returncode == 0, combined(result)
    # -it prints one member per line, so a filename containing a space stays
    # intact, and the set can be compared exactly.
    listed = {line for line in result.stdout.decode('utf-8', 'replace').splitlines() if line}
    assert listed == set(names), 'listed %s, expected %s' % (sorted(listed), sorted(names))


def test_copy_pass_interdir(tmp_path):
    """Copy-pass creates intermediate directories and keeps permission bits.

    From upstream interdir: `cpio -pd` creates en/to/tre as 0755, the copied
    dir as 0700 and the file as 0644, independent of the traversal order.
    """
    work = os.path.join(tmp_path, 'work')
    os.makedirs(os.path.join(work, 'dir'))
    with open(os.path.join(work, 'dir', 'file'), 'wb') as handle:
        handle.write(b'copied\n')
    os.chmod(os.path.join(work, 'dir'), 0o700)
    result = run_text(['cpio', '-pdvm', 'en/to/tre'], cwd=work,
        input='dir\ndir/file\n', umask=0o022)
    assert result.returncode == 0, result.stdout
    for rel, mode in (('en', 0o755), ('en/to', 0o755), ('en/to/tre', 0o755),
                      ('en/to/tre/dir', 0o700), ('en/to/tre/dir/file', 0o644)):
        path = os.path.join(work, rel)
        assert os.stat(path).st_mode & 0o777 == mode, '%s mode' % rel


@needs_cpio(2, 13)
def test_invalid_block_size(tmp_path):
    """An out-of-range --block-size is rejected instead of overflowing.

    From upstream big-block-size: cpio up to 2.12 accepted 20971520, which
    overflowed a signed integer; the check was added in 2.13.
    """
    tree = os.path.join(tmp_path, 'tree')
    os.makedirs(tree)
    with open(os.path.join(tree, 'file'), 'wb') as handle:
        handle.write(b'A' * 8)
    archive = copyout(tree, ['file'])

    out = os.path.join(tmp_path, 'out')
    result = copyin(archive, out, extra=['--block-size=20971520'])
    assert result.returncode == 2, combined(result)
    assert b'invalid block size' in combined(result), combined(result)
