import sys
from subprocess import *

p1 = Popen('./pwn 2>&1',stdin=PIPE, stdout=PIPE, shell=True)
p2 = Popen('./pwn 2>&1',stdin=PIPE, stdout=PIPE, shell=True)

out1 = p1.stdout.readline()
out2 = p2.stdout.readline()
print(out1[:-1].decode(), flush=True)

def interact(proc, line):
    alive = True
    try:
        proc.stdin.write(line)
        proc.stdin.flush()
    except Exception as e:
        alive = False
    return proc.stdout.readline(), alive

a1, a2 = True, True

while a1 and a2:
    line = sys.stdin.buffer.readline()
    out1, a1 = interact(p1, line)
    out2, a2 = interact(p2, line)
    if out1 != out2:
        print("Output conflict!", flush=True)
        print(f'process 1: {out1}', flush=True)
        print(f'process 2: {out2}', flush=True)
        break
    else:
        print(out1[:-1].decode(), flush=True)
