CLANG=$OSCFI_PATH/llvm-obj/bin/clang
CLANGPP=$OSCFI_PATH/llvm-obj/bin/clang++

OPT=$OSCFI_PATH/llvm-obj/bin/opt
LLC=$OSCFI_PATH/llvm-obj/bin/llc
DIS=$OSCFI_PATH/llvm-obj/bin/llvm-dis

OSCFG=$OSCFI_PATH/svf-src/debug-build/bin/oscfg
CFG=$OSCFI_PATH/llvm-obj/lib/LLVMInstCFG.so
PYSCRIPT=$OSCFI_PATH/pyScript/dumpData.py

OSCFI_LIB=$OSCFI_PATH/oscfi-lib-src/svf-cfg/

echo "++++++++++++++++Asking user input+++++++++++++++++++++++++"
echo "Enter target project source path (full path): "
read tarDir

echo "Enter target program name: "
read tarBin
echo "-----------------------------------------------------------------------"

echo "+++++++++++++++++++++Change directory to ""$tarDir""+++++++++++++++++++++++"
cd $tarDir

echo "++++++++++++++++++Copying OS-CFI Libs to project directory++++++++++++++++++++++"
rm -rf oscfi-libs
mkdir oscfi-libs
cp $OSCFI_LIB/* oscfi-libs/
echo "-----------------------------------------------------------------------"

echo "++++++++++++Building the target project (assuming Makefile has been modified as expected)+++++++++++"
export CC="$OSCFI_PATH""/llvm-obj/bin/clang"
export CXX="$OSCFI_PATH""/llvm-obj/bin/clang++"
export CFLAGS="-O0 -Xclang -disable-O0-optnone -flto -std=gnu89 -D_GNU_SOURCE -fpermissive -Wno-return-type -include oscfi-libs/oscfi.h -mmpx -pthread"
export CXXFLAGS="-O0 -Xclang -disable-O0-optnone -flto -std=c++03 -D_GNU_SOURCE -fpermissive -Wno-return-type -include oscfi-libs/oscfi.h -mmpx -pthread"
export LFILES="oscfi-libs/oscfi.o oscfi-libs/mpxrt.o oscfi-libs/mpxrt-utils.o"

make clean

$CC $CFLAGS -c oscfi-libs/oscfi.c -o oscfi-libs/oscfi.o
$CC $CFLAGS -c oscfi-libs/mpxrt.c  -o oscfi-libs/mpxrt.o
$CC $CFLAGS -c oscfi-libs/mpxrt-utils.c -o oscfi-libs/mpxrt-utils.o

make
echo "-----------------------------------------------------------------------"

echo "++++++++++++++++++CFG generation with SVF-SUPA++++++++++++++++++++++++"
$OSCFG -svfmain -cxt -query=funptr -maxcxt=10 -flowbg=10000 -cxtbg=100000 -cpts -print-query-pts "$tarDir""/""$tarBin"".0.4.opt.bc" > "$tarDir""/outs.txt" 2> "$tarDir""/stats.bin"
echo "-----------------------------------------------------------------------"

echo "+++++++++++++++++++Build the target program+++++++++++++++++++++++++"
$LLC -filetype=obj "$tarBin"".0.4.opt.oscfg.bc"
$CLANGPP -mmpx -pthread -O0  "$tarBin"".0.4.opt.oscfg.o" -o "$tarBin""_dump"
echo "-----------------------------------------------------------------------"

echo "+++++++++++++++++CFG table processing (1st phase)+++++++++++++++++++++"
objdump -s -j cfg_label_tracker "$tarBin""_dump" > dump_table.bin
python3 $PYSCRIPT $tarDir "$tarBin""_dump"
cp dump_table.bin dump_table.back
echo "-----------------------------------------------------------------------"

echo "++++++++++++++++++++++++++Optimization phase+++++++++++++++++++++++++++"
$OPT -load $CFG -llvm-inst-cfg -DIR_PATH="$tarDir" < "$tarBin"".0.4.opt.oscfg.bc" > "$tarBin"".0.4.opt.oscfg.opt.bc"
echo "-----------------------------------------------------------------------"

echo "+++++++++++++++Building the program with optimization++++++++++++++++++++++"
$LLC -filetype=obj "$tarBin"".0.4.opt.oscfg.opt.bc"
$CLANGPP -mmpx -pthread -O0 "$tarBin"".0.4.opt.oscfg.opt.o" -o "$tarBin""_opt"
echo "-----------------------------------------------------------------------"

echo "+++++++++++++++++CFG table processing (2nd phase)+++++++++++++++++++++"
objdump -s -j cfg_label_tracker "$tarBin""_opt" > dump_table.bin
python3 $PYSCRIPT $tarDir "$tarBin""_opt"
echo "-----------------------------------------------------------------------"

echo "+++++++++++++++++Instrumenting CFG to the binary+++++++++++++++++++++"
$OPT -load $CFG -llvm-inst-cfg -DIR_PATH="$tarDir" < "$tarBin"".0.4.opt.oscfg.bc" > "$tarBin"".0.4.opt.oscfg.cfg.bc"
echo "-----------------------------------------------------------------------"

echo "+++++++++++++++++++++++Final binary++++++++++++++++++++++++++++++"
$LLC -filetype=obj "$tarBin"".0.4.opt.oscfg.cfg.bc"
$CLANGPP -mmpx -pthread -O0 "$tarBin"".0.4.opt.oscfg.cfg.o" -o "$tarBin""_exec"
echo "-----------------------------------------------------------------------"

echo "+++++++++++++++++++++++Removing unnecessary files++++++++++++++++++++++++++++++"
rm -rf *.bin *.ll *.bc *.o
echo "-----------------------------------------------------------------------"

echo "+++++++++++++++++++++++Removing unnecessary files++++++++++++++++++++++++++++++"
mkdir -p run
cp -u "$tarBin""_exec" run/
echo "-----------------------------------------------------------------------"

echo "****************** Process complete. Check run/ for secured binary *****************"
