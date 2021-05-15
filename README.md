# Origin-sensitive Control Flow Integrity
We propose a new context for CFI, origin sensitivity, that can effectively break down large ECs and reduce the average and largest EC size. Origin-sensitive CFI (OS-CFI) takes the origin of the code pointer called by an ICT as the context and constrains the targets of the ICT with this context. It supports both C-style indirect calls and C++ virtual calls. Additionally, we leverage common hardware features in the commodity Intel processors (MPX and TSX) to improve both security and performance of OS-CFI. Our evaluation shows that OS-CFI can substantially reduce the largest and average EC sizes (by 98% in some cases) and has strong performance – 7.6% overhead on average for all C/C++ benchmarks of SPEC CPU2006 and NGINX.

*Note: Intel MPX is deprecated in latest CPU and kernel, so some part of code will require to adjust for latest.*

[Join us in the slack](https://join.slack.com/t/opencfi/shared_invite/enQtNzQ2MTM5MTA5NzM0LTdmMTQwZDU1YzEwNmE2ZDY4OTZiY2ExMDI1ZGVkOTdjYmYyNTNjNzVkOTYwNzdkNmY2OWNmMzhjMTUyNTJhZjc)

## IMPORTANT

This is a research prototype. Its sole purpose is to demonstrate that the original concept works. It is expected to have implementation flaws or can be broken/deprecated to latest sysyem. We welcome efforts to re-produce/evaluate our results but request an opportunity to fix any technical flaws. Generally speaking, we value design flaws more but will try to fix technical issues too.

**If you plan to use this project in production, we would love to hear about it and provide help if needed (Join our slack channel).**

This project is licensed in GPLv3 with the following additional conditions: 

1. If you plan to benchmark, compare, evaluate this project with intention to publish the results (including in a paper), you must first contact us with your real identity, affiliation, and advisors, and a short description of how you will use our source code (before any claim). In addition, you should provide an opportunity for us to comment on and help with technical and other issues related to this project. Examples include but are not limited to failure to compile or incomplete protection.

2. If you use any part of this project (excluding third-party software) and published a paper about it, you agree to open-source your project within one month of the paper (of any publicly available location) publication.

*Note: If you do not agree to these conditions, please do not use our source code.*

## Project Structure
- **llvm-src:** LLVM/Clang 7.0 Source Directory.
    - **clang/lib/CodeGen:** Fake reference monitor and metadata update Instrumentation.
    - **llvm/lib/Transforms/instCFG:** CFG, optimization, and original reference monitor instrumentation.
- **oscfi-lib-src:** OSCFI reference monitor and metadata source code.
- **svf-src:** Modified DDA to generate CFG and tag locations (for label-as-value).
- **pyScript:** Python code works on DDA generated CFG to reconstruct the original CFG.
- **testSuite:** Stores sample cases to test the project.
- **run.sh:** Bash script to run the OSCFI on any targeted project.

## Overall Process
- Step 1: Copy OSCFI monitor codes.
- Step 2: Build the target project with OSCFI clang/clang++.
- Step 3: Run SVF-SUPA (DDA) from OSCFI to generate the CFG. It also creates labels for translation (also known as  label-as-value).
- Step 4: Build the binary. Later, dump the section 'cfg_label_tracker' from the binary. Finally, run a python script to reconstruct the CFG.
- Step 5: Instrument the CFG using a LLVM pass.
- Step 6: Repeat step 4 and 5 to reconstruct the CFG due to optimization effect.
- Step 7: Build the final binary (secured by OSCFI).


## Installation Guideline
The following guideline assumes a fresh [ubuntu:21.04](https://github.com/tianon/docker-brew-ubuntu-core/blob/4b7cb6f04bc4054f9ab1fa42b549caa1a41b7c92/hirsute/Dockerfile) docker container has been used. We recommend to use the docker installation guideline (check above).

Following commands are for preparing basic tools:
```
apt update
apt upgrade
apt install git cmake g++ python python3-pip wget
```

Following commands are for preparing radare2 (a binary diassembler):
```
wget https://radare.mikelloc.com/get/4.5.0-git/radare2\_4.5.0-git\_amd64.deb
dpkg -i radare2\_4.5.0-git\_amd64.deb
pip install r2pipe
rm radare2\_4.5.0-git\_amd64.debrm radare2\_4.5.0-git\_amd64.deb
```

Following commands are for configuring the build:
```
git clone https://github.com/mustakimur/OS-CFI.git
echo "export OSCFI_PATH=\\"/home/OS-CFI\\"" >> ~/.profile
source ~/.profile
```

Following commands are for preparing Gold plugin build:
```
apt-get install linux-headers-5.11.0-17-generic csh gawk automake libtool bison flex libncurses5-dev
apt-get install apt-file texinfo texi2html
apt-file update
apt-file search makeinfo
```

Following commands are for building binutils required for Gold plugin:
```
cd /home
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
mkdir binutils-build
cd ../binutils-build
../binutils/configure --disable-gdb --enable-gold --enable-plugins --disable-werrorcd ../binutils-build/
make
```

Following commands are for building compiler with Gold plugin:
```
cd $OSCFI_PATH/
mkdir llvm-obj
cd llvm-obj/
cmake -DLLVM_BINUTILS_INCDIR="/home/binutils/include" -G "Unix Makefiles" ../llvm-src
make -j8
```

Following commands are for replacing existing binaries with Gold plugin binaries:
```
cd /home
mkdir backup
cd /usr/bin/

cp ar /home/backup/
cp nm /home/backup/
cp ld /home/backup/
cp ranlib /home/backup/

cp /home/binutils-build/binutils/ar ./
rm nm
cp /home/binutils-build/binutils/nm-new ./nm
cp /home/binutils-build/binutils/ranlib ./
cp /home/binutils-build/gold/ld-new ./ld

cd /usr/lib
cd bfd-plugins
cp $OSCFI_PATH/llvm-obj/lib/LLVMgold.so ./
cp $OSCFI_PATH/llvm-obj/lib/libLTO.* ./
```

Following commands are for building SVF-SUPA (for CFG generation):
```
cd $OSCFI_PATH/svf-src

export LLVM_SRC="$OSCFI_PATH/llvm-src"
export LLVM_OBJ="$OSCFI_PATH/llvm-obj"
export LLVM_DIR="$OSCFI_PATH/llvm-obj"
export PATH=$LLVM_DIR/bin:$PATH

mkdir debug-build
cd debug-build
cmake -D CMAKE_BUILD_TYPE:STRING=Debug ../
make -j4

export PATH=$OSCFI_PATH/svf-src/debug-build/bin:$PATH
```

## Spec Benchmark Build Guideline [deprecated: update soon]
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

## Sample Tests
- Vulnerable code exploitation prevented by OS-CFI:
```
cd testSuite
./test_run.sh
```

- For CPU2006spec 456.hmmer benchmark:
```
./test_hmmer.sh < inHmmer
```
