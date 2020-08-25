# Origin-sensitive Control Flow Integrity
We propose a new context for CFI, origin sensitivity, that can effectively break down large ECs and reduce the average EC size. Origin-sensitive CFI (OS-CFI) takes the origin of the code pointer called by the ICT as the context and constrains the targets of the ICT with this context. It supports both C-style indirect calls and C++ virtual calls. Additionally, we leverage common hardware features in the commodity Intel processors (MPX and TSX) to secure and improve the performance of reference monitors of OS-CFI. 

[Join us in the slack](https://join.slack.com/t/opencfi/shared_invite/enQtNzQ2MTM5MTA5NzM0LTdmMTQwZDU1YzEwNmE2ZDY4OTZiY2ExMDI1ZGVkOTdjYmYyNTNjNzVkOTYwNzdkNmY2OWNmMzhjMTUyNTJhZjc)

## IMPORTANT: Licensing

This project is licensed in GPLv3 with the following additional conditions: 

1. If you plan to benchmark, compare, evaluate this project with intention to publish the results (including in a paper), you must contact us with your real identity, affiliation, and advisors, and a short description of how you will use our source code before using and/or download this project. In addition, you will provide an opportunity for us to comment on and help with technical and other issues related to this project you have during the development. Examples include but are not limited to failure to compile or incomplete protection.

2. If you use any part of this project (excluding third-party software) and published a paper about it, you agree to open-source your project within one month of the official paper publication.

If you do not agree to these conditions, please do not use our source code.

**Justfication** This is a research prototype. Its sole purpose is to demonstrate that the original idea works. It is expected to have implementation flaws. We welcome efforts to re-produce/evaluate our results but request an opportunity to fix implementation flaws. Generally speaking, we value design flaws more but will try to fix implementation issues.
If you plan to use this project in production, we would love to hear about it and provide help if needed. 

## Project Structure
* llvm-src: LLVM/Clang 7.0 Source Directory
    * clang/lib/CodeGen: Instrumentation for update_mpx and reference monitor.
    * llvm/lib/Transforms/instCFG: Instrument CFG, optimize instrumentation, and replace reference monitor.
* oscfi-lib-src: OS-CFI source code for reference monitor and others.
* svf-src: lib/DDA is modified to use by tools/OSCFG.

## Overall Process
* Step 1: Copy the OSCFI enforcement code.
* Step 2: Build the project with clang/clang++.
* Step 3: Run the DDA based OSCFG tool to generate the CFG and create labels for translation.
* Step 4: Generate the binary, dump the section 'cfg_label_tracker', and run the python script to process the CFG.
* Step 5: Instrument the CFG with the optimization LLVM pass.
* Step 6: Repeat step 4 and 5 to adjust the CFG change due to optimization.
* Step 7: Generate final secure binary.


## Installation Guideline
1. Install required binary:
```text
sudo apt install cmake g++ gcc python bash git python-pip radare2
pip install r2pipe
```
2. Git clone the project:
```text
git clone https://github.com/mustakcsecuet/OS-CFI.git
cd OS-CFI
# copy the project path and save it
EDITOR ~/.profile
export OSCFI_PATH="$HOME/../OS-CFI"
```
***Note: You can skip step 3, 4, 5, 7, and 8 if you have already configured Gold plugin for another compiler.***

3. Install required library for Gold plugin:
```text
sudo apt-get install linux-headers-$(uname -r) csh gawk automake libtool bison flex libncurses5-dev
# Check 'makeinfo -v'. If 'makeinfo' does not exist
sudo apt-get install apt-file texinfo texi2html
sudo apt-file update
sudo apt-file search makeinfo
```

4. Download binutils source code:
```text
cd ~
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
```

5. Build binutils:
```text
mkdir build
cd build
../binutils/configure --enable-gold --enable-plugins --disable-werror
make
```

6. Build the compiler (use the binutils directory if you already have one):
```text
cd $OSCFI_PATH/
mkdir llvm-obj
cmake -DLLVM_BINUTILS_INCDIR="path_to_binutils/include" -G "Unix Makefiles" ../llvm-src
make -j8
```

7. Backup ar, nm, ld and ranlib:
```text
cd ~
mkdir backup
cd /usr/bin/
cp ar ~/backup/
cp nm ~/backup/
cp ld ~/backup/
cp ranlib ~/backup/
```

8. Replace ar, nm, ld and ranlib:
```text
cd /usr/bin/
sudo cp ~/build/binutils/ar ./
sudo rm nm
sudo cp ~/build/binutils/nm-new ./nm
sudo cp ~/build/binutils/ranlib ./
sudo cp ~/build/gold/ld-new ./ld
```

9. Install LLVMgold.so to /usr/lib/bfd-plugins:
```text
cd /usr/lib
sudo mkdir bfd-plugins
cd bfd-plugins
sudo cp $OSCFI_PATH/llvm_obj/lib/LLVMgold.so ./
sudo cp $OSCFI_PATH/llvm_obj/lib/libLTO.* ./
```

10. To Build SVF-SUPA:
```text
export LLVM_SRC=your_path_to_llvm-7.0.0.src
export LLVM_OBJ=your_path_to_llvm-7.0.0.obj
export LLVM_DIR=your_path_to_llvm-7.0.0.obj
export PATH=$LLVM_DIR/bin:$PATH

cd $OSCFI_HOME/svf-src
mkdir Debug-build
cd Debug-build
cmake -D CMAKE_BUILD_TYPE:STRING=Debug ../
make -j4

export PATH=$OSCFI_HOME/svf-src/Debug-build/bin:$PATH
```

## Spec Benchmark Build Guideline
1. Put spec2006-oscfi.cfg file into folder $CPU2006_HOME/config and analyze CPU2006 to generate bc files
```text
cd $CPU2006_HOME
. ./shrc
rm -rf benchspec/CPU2006/*/exe/
runspec  --action=run --config=spec2006-oscfi.cfg --tune=base --size=test --iterations=1 --noreportable all
```
2. Change the Makefile.spec in the build directory of the benchmark (e.g. ~/spec/benchspec/CPU2006/456.hmmer/build/build_base_amd64-m64-softbound-nn.0000/Makefile.spec):
```text
# add oscfi.c, mpxrt.c, mpxrt-utils.c in the source list, keep others same
SOURCES=oscfi.c mpxrt.c mpxrt-utils.c ...
```
3. Use the run.sh to start the system.

## Usage
* Try our sample exploitation:
```text
cd testSuite
./run.sh
```

* Try spec 456.hmmer benchmark:
```text
./run.sh < inHmmer
```
