CC=~/OS-CFI/llvm-obj/bin/clang
CXX=~/OS-CFI/llvm-obj/bin/clang++
DIS=~/OS-CFI/llvm-obj/bin/llvm-dis
OPT=~/OS-CFI/llvm-obj/bin/opt
OSCFG=~/OS-CFI/svf-src/Debug-build/bin/oscfg
PYSCRIPT=~/OS-CFI/pyScript/dumpData.py
LLC=~/OS-CFI/llvm-obj/bin/llc
CFG=~/OS-CFI/llvm-obj/lib/LLVMInstCFG.so

echo "Program Source Directory: "
read sourceDirectory

echo "Program Name:"
read progName

if [ ${sourceDirectory:0:1} == '~' ]
then
  sourceDirectory="$HOME""${sourceDirectory:1}"
fi 

echo "Build the program with initial instrumentation: "
cd $sourceDirectory
make clean
rm *.ll *.bc *.bin
make

echo "CFG generation with the help of DDA: "
$OSCFG -cxt -query=funptr -maxcxt=10 -flowbg=10000 -cxtbg=100000 -cpts -print-query-pts "$sourceDirectory""/""$progName"".0.4.opt.bc" > "$sourceDirectory""/outs.txt" 2> "$sourceDirectory""/stats.bin"
$DIS "$progName"".0.4.opt.oscfg.bc"

echo "Generate binary with labels: "
$LLC -filetype=obj "$progName"".0.4.opt.oscfg.bc"
$CXX -mmpx -pthread -O0  "$progName"".0.4.opt.oscfg.o" -o "$progName""_dump"

echo "Dump the tag table: "
objdump -s -j cfg_label_tracker "$progName""_dump" > dump_table.bin

echo "Run python script: "
python $PYSCRIPT $sourceDirectory "$progName""_dump"

echo "Instrument CFG: "
$OPT -load $CFG -llvm-inst-cfg -DIR_PATH="$sourceDirectory" < "$progName"".0.4.opt.oscfg.bc" > "$progName"".0.4.opt.oscfg.cfg.bc" 2> "$sourceDirectory""note.bin"
$DIS "$progName"".0.4.opt.oscfg.cfg.bc"

echo "Generate binary with labels: "
$LLC -filetype=obj "$progName"".0.4.opt.oscfg.cfg.bc"
$CXX -mmpx -pthread -O0 "$progName"".0.4.opt.oscfg.cfg.o" -o "$progName""_exec"
objdump -s -j cfg_label_tracker "$progName""_exec" > exec_table.bin

cp "$progName""_exec" run/
