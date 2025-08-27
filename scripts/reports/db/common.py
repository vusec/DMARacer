import yaml, os
from pymongo import MongoClient

NUM_PROCS = 32
INSPECT_BT = True
UNKNOWN_STR = '(?)'

# So that yaml.dump() prints numbers in hex (https://stackoverflow.com/a/42504639)
def hexint_presenter(dumper, data): return dumper.represent_int(hex(data))
yaml.add_representer(int, hexint_presenter)

# Mongo DB setup
client = MongoClient()
db=client.fetchdetector
reports_col = db.reports
lines_col = db.srclines # Documents contain fields: srcaddr, srcline, srcfile

def EXIT_ERR(msg=""):
    if msg: print(msg)
    terminate_all_processes()
    os._exit(1)

ppool = None
def terminate_all_processes():
    global ppool
    if ppool:
        print("Terminating all processes...")
        ppool.terminate()