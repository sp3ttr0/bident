#!/usr/bin/env python3
"""Run an isolated Responder installation with per-run output paths."""
import configparser
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def locate_installation():
    executable = shutil.which('responder')
    candidates = []
    if os.environ.get('RESPONDER_HOME'):
        candidates.append(Path(os.environ['RESPONDER_HOME']))
    if executable:
        candidates.append(Path(executable).resolve().parent)
    candidates.extend((Path('/usr/share/responder'), Path('/opt/Responder')))
    for path in candidates:
        if all((path / name).is_file() for name in ('Responder.py', 'settings.py', 'Responder.conf')):
            return path
    raise RuntimeError('Cannot locate Responder.py, settings.py and Responder.conf; set RESPONDER_HOME to the installation directory.')


def prepare(source, output):
    output = Path(output).resolve()
    logs, captures = output / 'logs', output / 'captures'
    for path in (output, logs, captures):
        if path.is_symlink():
            raise RuntimeError('Responder output directories must not be symbolic links.')
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    runtime = Path(tempfile.mkdtemp(prefix='bident-responder-'))
    try:
        shutil.copytree(source, runtime, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('logs', '*.db', '*.db-*', '__pycache__', '.git'),
                        symlinks=False)
        config = configparser.RawConfigParser()
        config.read(runtime / 'Responder.conf')
        core = 'Responder Core'
        config.set(core, 'Database', str(output / 'Responder.db'))
        for key, name in (('SessionLog', 'Responder-Session.log'),
                          ('PoisonersLog', 'Poisoners-Session.log'),
                          ('AnalyzeLog', 'Analyzer-Session.log'),
                          ('ResponderConfigDump', 'Config-Responder.log')):
            # Unique files preserve earlier logs when resuming the same results folder.
            config.set(core, key, str(logs / (runtime.name + '-' + name)))
        with (runtime / 'Responder.conf').open('w') as handle:
            config.write(handle)
        (runtime / 'logs').symlink_to(captures, target_is_directory=True)
        return runtime
    except BaseException:
        shutil.rmtree(runtime)
        raise


def restore_access(output, uid, gid):
    for directory, dirs, files in os.walk(output, followlinks=False):
        for path in [Path(directory)] + [Path(directory) / name for name in dirs + files]:
            if path.is_symlink():
                continue
            try:
                if uid is not None:
                    os.chown(path, uid, gid)
                path.chmod(0o700 if path.is_dir() else 0o600)
            except FileNotFoundError:
                pass  # SQLite sidecar files may disappear between enumeration and chmod.


def main():
    if len(sys.argv) != 5:
        raise RuntimeError('Usage: responder.py OUTPUT INTERFACE OWNER_UID OWNER_GID')
    output = Path(sys.argv[1]).resolve()
    uid, gid = (int(v) if v else None for v in sys.argv[3:5])
    runtime = prepare(locate_installation(), output)
    child = None
    pending = []

    def stop(signum, _frame):
        pending.append(signum)
        if child is not None and child.poll() is None:
            child.send_signal(signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stop)
    try:
        restore_access(output, uid, gid)
        child = subprocess.Popen([sys.executable, '-u', str(runtime / 'Responder.py'),
                                  '-I', sys.argv[2], '-dwv'], cwd=runtime)
        if pending:
            child.send_signal(pending[-1])
        while child.poll() is None:
            restore_access(output, uid, gid)
            if pending:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
            else:
                time.sleep(1)
        status = child.wait()
        if status != 0 and not pending:
            print('Responder: Incomplete: process exited with status ' + str(status), file=sys.stderr)
        return status
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        restore_access(output, uid, gid)
        shutil.rmtree(runtime)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('Responder: Incomplete: ' + str(error), file=sys.stderr)
        sys.exit(1)
