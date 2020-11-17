#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# IDA Python script doing nothing except printing hello world to be used by 
# idahunt.py command line:
# e.g. idahunt.py --scripts "/absolute/path/to/script_template.py"
# You can use this as a template to build your own scripts.
from idc import *
import os
import idautils
import time

time.sleep(3)
(INPUT_PATH,INPUT_FILE) = os.path.split(ida_nalt.get_input_file_path())
print("file path!!!:" + INPUT_PATH)
print("file name!!!:" + INPUT_FILE)
print("[script_template] I execute in IDA, yay!666")
# It is counter intuitive, but the IDA batch mode will pop the UI after executing the script by
# default, so this allows us to cleanly exit IDA and avoid the UI to pop-up upon completion
if "DO_EXIT" in os.environ:
   idc.qexit(1)