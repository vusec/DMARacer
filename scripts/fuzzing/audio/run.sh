#!/bin/sh

set -e
setenforce 0
echo "exec gnome-shell" > ~/.xinitrc
DISPLAY=:0 startx 1>/dev/null 2>/dev/null &
sleep 20 # Give some time for gnome to start up.
set +e

# Run some diagnostic stuff.
DISPLAY=:0 arecord -l
DISPLAY=:0 aplay -l
DISPLAY=:0 timeout 10 arecord --dump-hw-params
DISPLAY=:0 timeout 10 aplay --dump-hw-params

set -x
# Starts with 3 as that's the most common card slot.
for mainCard in 3 0 1 2; do
    for subCard in 0 1 2 3; do
        for format in S8 U8 S16_LE S16_BE U16_LE U16_BE S24_LE S24_BE U24_LE U24_BE S32_LE S32_BE U32_LE U32_BE FLOAT_LE FLOAT_BE FLOAT64_LE FLOAT64_BE IEC958_SUBFRAME_LE IEC958_SUBFRAME_BE MU_LAW A_LAW IMA_ADPCM MPEG GSM S20_LE S20_BE U20_LE U20_BE SPECIAL S24_3LE S24_3BE U24_3LE U24_3BE S20_3LE S20_3BE U20_3LE U20_3BE S18_3LE S18_3BE U18_3LE U18_3BE G723_24 G723_24_1B G723_40 G723_40_1B DSD_U8 DSD_U16_LE DSD_U32_LE DSD_U16_BE DSD_U32_BE ; do
            for channel in 1 2 ; do
                DISPLAY=:0 timeout 10 aplay --device="hw:${mainCard},${subCard}" /dev/urandom -f ${format} -c $channel
                DISPLAY=:0 timeout 10 arecord --device="hw:${mainCard},${subCard}" /tmp/file.wav -f ${format} -c $channel
            done
        done
    done
done

sleep 2