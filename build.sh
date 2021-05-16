apt update
apt upgrade
apt install git cmake g++ python python3-pip wget

wget https://radare.mikelloc.com/get/4.5.0-git/radare2\_4.5.0-git\_amd64.deb
dpkg -i radare2\_4.5.0-git\_amd64.deb
pip3 install r2pipe

git clone https://github.com/mustakimur/OS-CFI.git
echo "export OSCFI_PATH=\\"/home/OS-CFI\\"" >> ~/.profile
source ~/.profile

apt-get install linux-headers-5.11.0-17-generic csh gawk automake libtool bison flex libncurses5-dev
apt-get install apt-file texinfo texi2html
apt-file update
apt-file search makeinfo

cd /home
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
mkdir binutils-build
cd binutils-build
../binutils/configure --disable-gdb --enable-gold --enable-plugins --disable-werror
make

cd $OSCFI_PATH/
mkdir llvm-obj
cd llvm-obj/
cmake -DLLVM_BINUTILS_INCDIR="/home/binutils/include" -G "Unix Makefiles" ../llvm-src
make -j8

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
