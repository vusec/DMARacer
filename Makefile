ROOT=.
KERNEL=${ROOT}/kdfsan-df-linux
include ${ROOT}/.env
export ROOT
export KERNEL
export GDB_PORT
gdb:
	GDB=gdb-multiarch scripts/run-gdb.sh
