# ATC24: Fast (Trapless) Kernel Probes Everywhere

#### Environment setup
This artifact uses Docker to setup the environment. Please make sure Docker
is installed before move on.

First, clone the repo:
```shell
git clone git@github.com:hardos-ebpf-fuzzing/atc24-uno-kprobe.git
```
Then, build the Docker image:
```shell
cd atc24-uno-kprobe
docker build . -t 'kprobe'
```
This step may take a while, as it builds our modified `llvm` together with
`clang` and `lld`.


#### Build and benchmark the un-optimized kernel
Enter the Docker container first:
```shell
# working dir should be /atc24/ upon entry
docker run -it --device=/dev/kvm kprobe bash
```

Switch to the kernel directory:
```shell
cd linux
```

Build the kernel with the unmodified distro LLVM toolchain:
```shell
make LLVM=1 olddefconfig
make LLVM=1 -j`nproc`
```

Build the userspace benchmark program:
```shell
make -C ..
```

Boot the kernel with QEMU:
```shell
../q
```

The QEMU script uses overlayfs to create a mirroring of host file system,
so upon entering the VM, the current directory is still the kernel
directory.

Register the kprobe onto a test system call we created:
```shell
insmod ./samples/kprobe/kprobe_example.ko
```
This step registers a kprobe onto the instruction we crafted in the
`kprobe_bench_test_func` function. This instruction is not optimizable by
current Linux. The `kprobe_bench_test_func` measures the time it takes to
execute the instruction (together with all the kprobe operations) using the
`RDTSC` and `RDTSCP` instructions, which returns the time in terms of
processor cycles. The elaped time is then sent to userspace via the return
value of our `kprobe_bench` system call.

Run the userspace benchmark program to benchmark the unoptimized kprobe
performance:
```shell
../test
```

When done, use `Control-D` to exit the VM

#### Build and benchmark the optimized kernel
The implementation details of the LLVM pass can be found under
`llvm-project/llvm/lib/Target/X86/X86KprobeOpt.cpp`; the kernel side
support code is under `linux/arch/x86/kernel/kprobes/nop-opt`.


Again, enter the Docker container
```shell
docker run -it --device=/dev/kvm kprobe bash
```

Add our modified LLVM to `PATH`:
```shell
export PATH=`realpath ./llvm-project/build/bin`:$PATH
```

Configure the kernel to enable uno-kprobe optimization:
```shell
cd linux
./scripts/config -e KPROBES_NOP_OPT
make LLVM=1 olddefconfig
```

Build the kernel again
```shell
make LLVM=1 -j`nproc`
```

Build the userspace benchmark program:
```shell
make -C ..
```

Boot the kernel with QEMU:
```shell
../q
```

Register the kprobe onto a test system call we created:
```shell
insmod ./samples/kprobe/kprobe_example.ko
```

Run the userspace benchmark program to benchmark the optimized kprobe
performance:
```shell
../test
```
