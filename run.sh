CC=~/OS-CFI/llvm-obj/bin/clang
CXX=~/OS-CFI/llvm-obj/bin/clang++
DIS=~/OS-CFI/llvm-obj/bin/llvm-dis
OPT=~/OS-CFI/llvm-obj/bin/opt
OSCFG=~/OS-CFI/svf-src/Debug-build/bin/oscfg
PYSCRIPT=~/OS-CFI/pyScript/dumpData.py
LLC=~/OS-CFI/llvm-obj/bin/llc
CFG=~/OS-CFI/llvm-obj/lib/LLVMInstCFG.so
OSCFI_LIB=~/OS-CFI/oscfi-lib-src/svf-cfg/

echo "Please, modify the Makefile.spec according to the README.md ..."
read -p "Press any key to continue ..."

echo "Enter project directory (Target source): "
read sourceDirectory

echo "Enter project name (Target binary name): "
read progName

if [ ${sourceDirectory:0:1} == '~' ]
then
  sourceDirectory="$HOME""${sourceDirectory:1}"
fi 

echo "In project directory ..."
cd $sourceDirectory

echo "Copying OS-CFI Libs to project directory ..."
cp $OSCFI_LIB/* .

echo "Building the project ..."
make clean
rm *.ll *.bc *.bin
make

echo "Static points-to analysis CFG generation ..."
$OSCFG -cxt -query=funptr -maxcxt=10 -flowbg=10000 -cxtbg=100000 -cpts -print-query-pts "$sourceDirectory""/""$progName"".0.4.opt.bc" > "$sourceDirectory""/outs.txt" 2> "$sourceDirectory""/stats.bin"
$DIS "$progName"".0.4.opt.oscfg.bc"

echo "Generating the binary ..."
$LLC -filetype=obj "$progName"".0.4.opt.oscfg.bc"
$CXX -mmpx -pthread -O0  "$progName"".0.4.opt.oscfg.o" -o "$progName""_dump"

echo "Dumping CFG table and run python script ..."
objdump -s -j cfg_label_tracker "$progName""_dump" > dump_table.bin
python $PYSCRIPT $sourceDirectory "$progName""_dump"
cp dump_table.bin dump_table.back

echo "Optimization phase ..."
$OPT -load $CFG -llvm-inst-cfg -DIR_PATH="$sourceDirectory" < "$progName"".0.4.opt.oscfg.bc" > "$progName"".0.4.opt.oscfg.opt.bc"
$DIS "$progName"".0.4.opt.oscfg.opt.bc"

echo "Generating the binary with optimization ..."
$LLC -filetype=obj "$progName"".0.4.opt.oscfg.opt.bc"
$CXX -mmpx -pthread -O0 "$progName"".0.4.opt.oscfg.opt.o" -o "$progName""_opt"

echo "Dumping CFG table and run python script ..."
objdump -s -j cfg_label_tracker "$progName""_opt" > dump_table.bin
python $PYSCRIPT $sourceDirectory "$progName""_opt"

echo "CFG Instrumentation phase ..."
$OPT -load $CFG -llvm-inst-cfg -DIR_PATH="$sourceDirectory" < "$progName"".0.4.opt.oscfg.bc" > "$progName"".0.4.opt.oscfg.cfg.bc"
$DIS "$progName"".0.4.opt.oscfg.cfg.bc"

echo "Generating the secure binary with optimization ..."
$LLC -filetype=obj "$progName"".0.4.opt.oscfg.cfg.bc"
$CXX -mmpx -pthread -O0 "$progName"".0.4.opt.oscfg.cfg.o" -o "$progName""_exec"

cp "$progName""_exec" run/

cd run/
./"$progName""_exec" nph3.hmm swiss41
