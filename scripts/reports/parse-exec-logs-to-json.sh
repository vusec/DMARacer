#!/bin/bash

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 OUT.json EXEC_LOG_1 EXEC_LOG_2 ..."
    exit 1
fi

JSON_FILE=$1
shift

# Parse out each report and add the "dev" field to it
JSON=""
for EXEC_LOG in "$@"
do
    echo "Parsing reports from ${EXEC_LOG}..."
    DEV=$(basename ${EXEC_LOG})
    DEV="${DEV%%.*}"
    DEV="${DEV##dev-}"
    JSON+=$'\n'
    JSON+=$(grep "KDFSAN REPORT: " ${EXEC_LOG} | tr -d '\r' | grep "\}$" | sed 's/.*KDFSAN REPORT: //' | sed "s/\"report_id\":/\"dev\": \"${DEV}\", \"report_id\":/")
done

echo "Saving reports to ${JSON_FILE}..."
echo "${JSON}" | grep -v "^$" | sed '1s/^/[/;$!s/$/,/;$s/$/]/' > ${JSON_FILE}

python3 -mjson.tool ${JSON_FILE} > /dev/null || { echo "Error: Parsed JSON in file $(readlink -f ${JSON_FILE}) is misformatted. Check if e.g., the final object in the array is misformatted because the log was cut off mid-report. Fix the log, then re-run." ; exit 1 ; }

