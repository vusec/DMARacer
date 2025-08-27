#!/usr/bin/env python3

import subprocess as sp
import pathlib
import os
import sys
import re

def clean_str(s : str) -> str:
    return s.replace("-", "").replace("/", "").replace("_", "")

def remove_blubber(s : str) -> str:
    to_remove = [",serial", "-pci", "pci-", "usb-", "-uhci", "-xhci", "-vga", "-device", "-ide", "-subsys", "isa-"]
    for t in to_remove:
        s = s.replace(t, "")
    return s

class ConfigOption:
    def __init__(self, lines):
        start_line = lines[0]
        name = start_line.split()[1]
        self.name = name
        self.dependencies = []
        self.config_name = "CONFIG_" + name
        self.description = ""
        for line in lines[1:]:
            if line != "" and line.lstrip() == line:
                break
            self.parse_dep_line(line)
            self.description += line.lstrip().lower()
        self.description = clean_str(self.description)

    def add_dep(self, dep : str):
        self.dependencies.append(dep)
        self.dependencies = list(set(self.dependencies))

    def parse_dep_line(self, line : str):
        line = line.strip()
        prefix = "depends on "
        if not line.startswith(prefix):
            return
        line = line[len(prefix):]

        parts = line.split("&&")
        for part_out in parts:
            for part in part_out.split("||"):
                part = part.strip()
                if "=" in part:
                    part = part.split("=")[0]
                self.add_dep(part)

config_options = {}
def scan_lines(lines):
    global config_options
    for i in range(0, len(lines)):
        line = lines[i]
        if line.startswith("config"):
            new_config = ConfigOption(lines[i:])
            config_options[new_config.name] = new_config

config_files = sorted(pathlib.Path('.').glob('**/Kconfig'))
print("Found " + str(len(config_files)) + " config files")

for config_file in config_files:
    if not os.path.isfile(config_file):
        continue
    with open(config_file, "r") as f:
        scan_lines(f.readlines())

print("Found config options: " + str(len(config_options)))

driver_files = [
    "scripts/fuzzing/audio/host/qemu-audio-x86",
    "scripts/fuzzing/gpu/host/qemu-gpus-x86",
    "scripts/fuzzing/input/host/qemu-inputs-x86",
    "scripts/fuzzing/storage/host/devices-x86",
]

wanted_drivers = []
for f in driver_files:
    with open(f, "r") as f:
        for line in f.readlines():
            wanted_drivers.append(line.strip())

activated = []

def activate_driver(d : ConfigOption):
    global activated
    if d.config_name in activated:
        return
    for dep in d.dependencies:
        if not dep in config_options:
            print(f"Warning: Could not find {dep}")
            continue
        activate_driver(config_options[dep])
    activated.append(d.config_name)

def activate_related_drivers(driver_name) -> bool:
    found = False
    for config in config_options.values():
        config = config # type: ConfigOption
        if config.name.lower() == driver_name.lower():
            #print("Found exact match: " + driver_name)
            activate_driver(config)
            found = True
    if found: return found

    for config in config_options.values():
        config = config # type: ConfigOption
        if clean_str(driver_name) in config.description:
            #print("Found description match: " + config.name)
            #print("#######################################################")
            #print(config.description)
            #print("#######################################################")
            activate_driver(config)
            found = True
    if found: return found
    
    cleaned = remove_blubber(driver_name)
    if cleaned != driver_name:
        return activate_related_drivers(cleaned)
    if "-" in driver_name:
        for part in driver_name.split("-"):
            return activate_related_drivers(part)

    numbers = re.findall('[0-9]+', driver_name)
    for number in numbers:
        # Prevent infinite recursion.
        if number == driver_name:
            break
        if len(number) <= 2:
            continue

        found |= activate_related_drivers(number)
    return found

for wanted_driver in wanted_drivers:
    if not activate_related_drivers(wanted_driver):
        print("Failed to find driver for: " + wanted_driver)

print("Acivated:\n" + "\n".join(list(set(activated))))
#for c in config_options:
#    print("C: " + c.config_name)
#    print("C: " + c.description)
