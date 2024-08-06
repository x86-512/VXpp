# vfgadget-finder

This is a simple script that looks for usable vfgadgets in a COOP attack. COOP is an exploitation technique that bypasses advanced security mitigations like Intel CET.

Currently, this project is very limited in functionality. The script only searches for a main loop gadget involving a vtable function call. I am currently working on functionality to add more specific criteria for jumps, cfg/xfg checks, limiting function size, a usability index, and an XFG function hash comparison.

How to run:
- Install ghidra
- Install requirements: ```pip install pyhidra```
- Load the file in ghidra
- Run the script
