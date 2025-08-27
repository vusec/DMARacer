#!/bin/sh

FDATE=$(date +"%Y-%m-%d-%H:%M:%S")
set -x
mongodump -d fetchdetector --gzip --archive=out/${FDATE}.db_backup.gz
