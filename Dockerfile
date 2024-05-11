FROM ubuntu:24.04
RUN apt update
RUN apt install -y build-essential clang llvm lld mold git bc libncurses-dev wget busybox libssl-dev libelf-dev dwarves flex bison qemu-system-x86 cmake ninja-build

COPY ./llvm-project/ /atc24/llvm-project
COPY ./linux /atc24/linux
COPY ./kernel.config /atc24/linux/.config
COPY ./Makefile /atc24/Makefile
COPY ./test.c /atc24/test.c

WORKDIR "/atc24/llvm-project"
RUN cmake -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=x86_64-linux-gnu-gcc -DCMAKE_CXX_COMPILER=x86_64-linux-gnu-g++ -DCMAKE_C_FLAGS="-pipe" -DCMAKE_CXX_FLAGS="-pipe" -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_USE_LINKER=mold -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_PARALLEL_LINK_JOBS=2 -DLLVM_ENABLE_ASSERTIONS=ON -Sllvm -Bbuild && cmake --build ./build

COPY ./q /atc24/q

WORKDIR "/atc24/"
RUN chmod u+x /atc24/q
RUN apt install -y iproute2 kmod xterm
