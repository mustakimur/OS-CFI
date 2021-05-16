FROM ubuntu:21.04

COPY llvm-src /home/OS-CFI/llvm-src/
COPY oscfi-lib-src /home/OS-CFI/oscfi-lib-src/
COPY pyScript /home/OS-CFI/pyScript/
COPY svf-src /home/OS-CFI/svf-src/
COPY testSuite /home/OS-CFI/testSuite/
COPY build.sh /home/OS-CFI/
COPY run.sh /home/OS-CFI/
COPY README.md /home/OS-CFI/
COPY inHmmer /home/OS-CFI/
COPY spec2006-oscfi.cfg /home/OS-CFI/
COPY LICENSE /home/OS-CFI/

ENV DEBIAN_FRONTEND=noninteractive

RUN chmod +x /home/OS-CFI/build.sh && \
    chmod +x /home/OS-CFI/run.sh && \
    chmod +x /home/OS-CFI/testSuite/test_run.sh

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install git cmake g++ python wget

RUN apt-get -q -y install python3-pip

RUN cd /home/ && \
    wget https://radare.mikelloc.com/get/4.5.0-git/radare2\_4.5.0-git\_amd64.deb && \
    dpkg -i radare2\_4.5.0-git\_amd64.deb && \
    pip3 install r2pipe && \
    rm -f radare2\_4.5.0-git\_amd64.debrm radare2\_4.5.0-git\_amd64.deb

ENV OSCFI_PATH="/home/OS-CFI"

RUN apt-get -y install linux-headers-5.11.0-17-generic csh gawk automake libtool bison flex libncurses5-dev && \
    apt-get -y install apt-file texinfo texi2html && \
    apt-file update && \
    apt-file search makeinfo

RUN cd /home && \
    git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils && \
    mkdir binutils-build && \
    cd binutils-build && \
    ../binutils/configure --disable-gdb --enable-gold --enable-plugins --disable-werror && \
    make

RUN cd $OSCFI_PATH/ && \
    mkdir llvm-obj && \
    cd llvm-obj/ && \
    cmake -DLLVM_BINUTILS_INCDIR="/home/binutils/include" -G "Unix Makefiles" ../llvm-src && \
    make -j8

RUN cd /home && mkdir backup && cd /usr/bin/ && \
    cp ar /home/backup/ && cp nm /home/backup/ && cp ld /home/backup/ && \
    cp ranlib /home/backup/ && cp /home/binutils-build/binutils/ar ./ && \
    rm nm && cp /home/binutils-build/binutils/nm-new ./nm && \
    cp /home/binutils-build/binutils/ranlib ./ && \
    cp /home/binutils-build/gold/ld-new ./ld && \
    cd /usr/lib && cd bfd-plugins && \
    cp $OSCFI_PATH/llvm-obj/lib/LLVMgold.so ./ && \
    cp $OSCFI_PATH/llvm-obj/lib/libLTO.* ./

ENV LLVM_SRC="$OSCFI_PATH/llvm-src"
ENV LLVM_OBJ="$OSCFI_PATH/llvm-obj"
ENV LLVM_DIR="$OSCFI_PATH/llvm-obj"
ENV PATH=$LLVM_DIR/bin:$PATH

RUN cd $OSCFI_PATH/svf-src && \
    mkdir debug-build && \
    cd debug-build && \
    cmake -D CMAKE_BUILD_TYPE:STRING=Debug ../ && \
    make -j4

ENV PATH=$OSCFI_PATH/svf-src/debug-build/bin:$PATH

CMD ["cd", "/home/OS-CFI"]
