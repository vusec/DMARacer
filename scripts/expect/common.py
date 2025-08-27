import sys
import os
import argparse
import subprocess
import pexpect
import atexit
import signal
import socket
import tempfile
from time import sleep

SYZKALLER_IMG = os.environ['SYZKALLER_IMG']
QEMUSOCKET = None
SYZKALLER_SSH_PORT = None

def reserve_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    return port, sock

def init_syzkaller_port():
    global SYZKALLER_SSH_PORT
    if SYZKALLER_SSH_PORT: return
    p,_ = reserve_port()
    SYZKALLER_SSH_PORT = p
    os.environ['SYZKALLER_SSH_PORT'] = '{}'.format(SYZKALLER_SSH_PORT)

def init_qemu_socket():
    global QEMUSOCKET
    if QEMUSOCKET: return
    p = tempfile.NamedTemporaryFile().name
    QEMUSOCKET = p
    os.environ['QEMUSOCKET'] = '{}-interact'.format(p)

def getch():
    import sys, tty, termios
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def expect(qemu, expect, kill_on_timeout=True, kill_on_panic=True, timeout=30):
    i = qemu.expect([
        pexpect.TIMEOUT,
        expect],
        timeout=timeout)
    if i == 0 and kill_on_timeout:
        print('TIMEOUT')
        sys.exit(-1)
    if i >= 2 and kill_on_panic:
        print('PANIC')
        sys.exit(-1)

def exec_command(command):
    process = subprocess.Popen(command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if stderr:
        print('error: {}'.format(stderr.decode("utf-8")))
        return None
    return stdout.decode("utf-8").splitlines()

def socat_command(command, qemusocket):
    echo = subprocess.Popen(['echo', command], stdout=subprocess.PIPE)
    try:
        output = subprocess.check_output(
                ['socat', '-t', '100000', '-', 'unix-connect:{}'.format(qemusocket)],
                stdin=echo.stdout)
        echo.wait()
    except:
        print('{} failed'.format(command))
        sys.exit(-1)

def snapshot_save(snapshot):
    print('Saving snapshot as {}'.format(snapshot))
    socat_command('savevm {}'.format(snapshot), QEMUSOCKET)

def snapshot_load(snapshot):
    print('Loading snapshot as {}'.format(snapshot))
    socat_command('loadvm {}'.format(snapshot), QEMUSOCKET)

def copy_files(testprogs):
    print('Copying files onto VM from "' + testprogs + '"...')
    exec_command([
        'sh', '-c',
        'scp -i {}/bullseye.id_rsa -o StrictHostKeyChecking=no -P {} {} root@localhost:/root 2>/dev/null'.format(
            SYZKALLER_IMG, SYZKALLER_SSH_PORT, testprogs)])

def copy_testcases(testprogs_path):
    testprogs = '{}/*.bin'.format(testprogs_path)
    copy_files(testprogs, SYZKALLER_SSH_PORT)

def get_host_ip():
    return subprocess.run(['sh', '-c', "ip a | grep 'inet 10\\.\\|inet 172\\.\\|inet 192\\.168' | sed 's/.*inet //' | sed 's/\\/[0-9].*//' | head -1 | tr -d '\\n'"], stdout=subprocess.PIPE).stdout.decode('utf-8')

def kill_proc(p):
    os.killpg(os.getpgid(p.pid), signal.SIGTERM)

def start_http_server_proc(ip, port, output_path):
    print("Starting HTTP server process (ip:"+ip+", port:"+str(port)+", output_path:"+output_path+")...")
    f = open(output_path, "w")
    p = subprocess.Popen(['python3', '-m', 'http.server', '--bind', ip, str(port)], preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=f)
    atexit.register(kill_proc, p)
