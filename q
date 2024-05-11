#!/bin/bash
# based on: https://github.com/fomichev/dotfiles/blob/master/bin/q

usage() {
	echo "q [options] [path to bzImage] [script]"
	echo
	echo "Run it from the kernel directory (make sure .config is there)"
	echo
	echo "options:"
	echo "    m - run depmod and modprobe"
	echo "    c - pass extra kernel cmdline options"
	echo "    s - start SSH server"
	exit 1
}

# This function is called _BEFORE_ QEMU starts (on host).
host() {
	local kernel="$1"
	shift

	if [ -z "$kernel" ]; then
		if [ -e "arch/x86/boot/bzImage" ]; then
			kernel="arch/x86/boot/bzImage"
		fi
		[ -n "$kernel" ] || usage
	fi
	[ -e ".config" ] || usage

	local cmdline

	local fs
	fs+=" -nodefaults"
	fs+=" -fsdev local,multidevs=remap,id=vfs1,path=/,security_model=none,readonly=on"
	fs+=" -fsdev local,multidevs=remap,id=vfs2,path=$(pwd),security_model=none"
	fs+=" -device virtio-9p-pci,fsdev=vfs1,mount_tag=/dev/root"
	fs+=" -device virtio-9p-pci,fsdev=vfs2,mount_tag=/dev/kernel"

	local console
	console+=" -display none"
	console+=" -serial mon:stdio"
	console+=" -serial tcp::1235,server,nowait"

	cmdline+=" earlyprintk=serial,ttyS0,115200"
	cmdline+=" console=ttyS0,115200"
	cmdline+=" kgdboc=ttyS1,115200"

	local net
	if [ "$SSH" = "y" ]; then
		net+=" -netdev user,id=virtual,hostfwd=tcp:127.0.0.1:52222-:22"
	else
		net+=" -netdev user,id=virtual"
	fi
	net+=" -device virtio-net-pci,netdev=virtual"

	local opts
	[ "$MODULES" = "y" ] && opts+=" -m"
	[ "$SSH" = "y" ] && opts+=" -s"

	cmdline+=" rootfstype=9p"
	cmdline+=" rootflags=version=9p2000.L,trans=virtio,msize=104857600,access=any"
	cmdline+=" ro"
	cmdline+=" nokaslr"
	cmdline+=" $CMDLINE"
	cmdline+=" init=/bin/sh -- -c \"$(realpath $0) -g $opts -H $HOME -k '$(pwd)' -a '$*'\""

	qemu-system-x86_64 \
		-nodefaults \
		-no-reboot \
		-machine accel=kvm:tcg \
		-device i6300esb \
		-device virtio-rng-pci \
		-cpu host \
		-smp $NRCPU \
		-m $MEMORY \
		$fs \
		$console \
		$net \
		$QEMUARG \
		-kernel "$kernel" \
		-append "$cmdline" -s

	# qemu-system-x86_64 \
	# 	-nodefaults \
	# 	-d int \
	# 	-machine accel=tcg \
	# 	-watchdog i6300esb \
	# 	-device virtio-rng-pci \
	# 	-cpu max \
	# 	-smp $NRCPU \
	# 	-m $MEMORY \
	# 	$fs \
	# 	$console \
	# 	$net \
	# 	$QEMUARG \
	# 	-kernel "$kernel" \
	# 	-append "$cmdline" -s
}

say() {
	trap 'tput sgr0' 2 #SIGINT
	tput setaf 2
	echo ">" "$@"
	tput sgr0
}

# This function is called _AFTER_ QEMU starts (on guest).
guest() {
	export PATH=/bin:/sbin:/usr/bin:/usr/sbin

	say pivot root

	mount -n -t proc -o nosuid,noexec,nodev proc /proc/

	mount -n -t tmpfs tmpfs /tmp
	mkdir -p /tmp/rootdir-overlay/{lower,upper,work,mnt}
	mount --bind / /tmp/rootdir-overlay/lower
	mount -t overlay overlay -o lowerdir=/tmp/rootdir-overlay/lower,upperdir=/tmp/rootdir-overlay/upper,workdir=/tmp/rootdir-overlay/work /tmp/rootdir-overlay/mnt
	pivot_root /tmp/rootdir-overlay/mnt{,/mnt}
	cd /

	say early setup

	mount -n -t sysfs -o nosuid,noexec,nodev sys /sys/

	mount -n -t tmpfs tmpfs /tmp
	mount -n -t tmpfs tmpfs /var/log
	mount -n -t tmpfs tmpfs /run

	rm -f /etc/fstab
	touch /etc/fstab

	mount -n -t proc -o nosuid,noexec,nodev proc /proc/
	mount -n -t configfs configfs /sys/kernel/config
	mount -n -t debugfs debugfs /sys/kernel/debug
	mount -n -t securityfs security /sys/kernel/security
	mount -n -t devtmpfs -o mode=0755,nosuid,noexec devtmpfs /dev

	mkdir -p -m 0755 /dev/shm /dev/pts
	mount -n -t devpts -o gid=tty,mode=620,noexec,nosuid devpts /dev/pts
	mount -n -t tmpfs -o mode=1777,nosuid,nodev tmpfs /dev/shm

	ln -s /proc/self/fd /dev/fd

	mount --move /mnt /tmp
	mount -n -t tmpfs tmpfs /mnt
	mkdir /mnt/base-root
	mount --move /tmp /mnt/base-root

	local kver="`uname -r`"
	local mods="$(find /sys/devices -type f -name modalias -print0 | xargs -0 cat | sort | uniq)"
	local mods_nr=$(echo "$mods" | wc -w)

	say modules /lib/modules/$kver $mods_nr modules
	mount -n -t 9p -o version=9p2000.L,trans=virtio,msize=104857600 /dev/kernel $KERNEL
	mount -n -t tmpfs tmpfs /lib/modules
	mkdir "/lib/modules/$kver"
	ln -s $KERNEL "/lib/modules/$kver/source"
	ln -s $KERNEL "/lib/modules/$kver/build"
	ln -s $KERNEL "/lib/modules/$kver/kernel"

	cp $KERNEL/modules.builtin "/lib/modules/$kver/modules.builtin"
	cp $KERNEL/modules.builtin.modinfo "/lib/modules/$kver/modules.builtin.modinfo"
	cp $KERNEL/modules.order "/lib/modules/$kver/modules.order"

	# make sure config points to the right place
	mount -n -t tmpfs tmpfs /boot
	ln -s $KERNEL/.config /boot/config-$kver

	if [ "$MODULES" = "y" ]; then
		if [ ! -e $KERNEL/modules.dep.bin ]; then
			say modules.dep.bin not found, running depmod, may take awhile
			depmod -a 2>/dev/null
		fi
		modprobe -q -a -- $mods
	fi

	say networking

	hostname q
	rm -f /etc/hostname
	echo q > /etc/hostname

	ip link set dev lo up

	rm -f /etc/resolv.conf
	echo "nameserver 8.8.8.8" > /etc/resolv.conf

	local dev=$(ls -d /sys/bus/virtio/drivers/virtio_net/virtio* |sort -g |head -n1)
	local iface=$(ls $dev/net)
	say dhcp on iface $iface
	ip link set dev $iface up
	busybox udhcpc -i $iface -p /run/udhcpc \
		-s /usr/share/udhcpc/default.script -q -t 1 -n -f

	say setup cgroups
	sysctl -q kernel.allow_bpf_attach_netcg=0 &>/dev/null
	mount -t cgroup2 none /sys/fs/cgroup

	say setup bpf
	sysctl -q net.core.bpf_jit_enable=1
	sysctl -q net.core.bpf_jit_kallsyms=1
	sysctl -q net.core.bpf_jit_harden=0
	mount -t bpf bpffs /sys/fs/bpf
	ulimit -l unlimited &>/dev/null # EINVAL when loading more than 3 bpf programs
	ulimit -n 819200 &>/dev/null
	ulimit -a &>/dev/null

	say root passwd
	rm -f /etc/{shadow,gshadow}
	pwconv
	grpconv

	mount --bind / /mnt
	usermod -R /mnt -d "$HOME" root
	umount /mnt

	if [ "$SSH" = "y" ]; then
		say setup sshd: '$ ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost -p 52222'
		mask-dir () {
			touch "$1"
			setfattr -n trusted.overlay.opaque -v y /mnt/base-root/tmp/rootdir-overlay/upper/"$1"
			mount -o remount /
		}
		mask-dir /etc/ssh/

		cat << 'EOF' > /etc/pam.d/sshd
account sufficient pam_permit.so
auth sufficient pam_permit.so
password sufficient pam_permit.so
session sufficient pam_permit.so
EOF

		ssh-keygen -A
		`which sshd` -p 22 -o UsePAM=yes -o PermitRootLogin=yes -f /dev/null -E /var/log/sshd
	fi

	say root environment

cat << EOF >> $HOME/.profile
export KERNEL=$KERNEL

export PATH=\$HOME/local/bin:\$PATH
export PATH=\$KERNEL/tools/bpf/bpftool:\$PATH
export PATH=\$KERNEL/tools/perf:\$PATH
EOF

	cat << EOF >> $HOME/.bashrc
mask-dir () {
	touch "\$1"
	setfattr -n trusted.overlay.opaque -v y /mnt/base-root/tmp/rootdir-overlay/upper/"\$1"
	mount -o remount /
}

source $KERNEL/tools/bpf/bpftool/bash-completion/bpftool

eval \$(resize)
EOF

	cd $KERNEL

	if [ -n "$ARGS" ]; then
		say non-interactive bash script
		setsid bash -l -c "$ARGS"
		if [ ! $? -eq 0 ]; then
			say script failed, starting interactive console
			setsid bash -l 0<>"/dev/ttyS0" 1>&0 2>&0
		fi
	else
		say interactive bash
		setsid bash -l 0<>"/dev/ttyS0" 1>&0 2>&0
	fi

	echo
	say poweroff
	poweroff -f
	echo o > /proc/sysrq-trigger
	sleep 30
}

GUEST=n
MODULES=n
SSH=n
CMDLINE=""
QEMUARG=""

NRCPU=4
MEMORY=2048

while getopts "hgmsk:c:a:H:N:M:q:" opt; do
	case $opt in
		h) usage ;;
		g) GUEST=y ;;
		m) MODULES=y ;;
		s) SSH=y ;;
		k) KERNEL="$OPTARG" ;;
		c) CMDLINE="$OPTARG" ;;
		a) ARGS="$OPTARG" ;;
		H) export HOME=$OPTARG ;;
		M) MEMORY="$OPTARG" ;;
		N) NRCPU="$OPTARG" ;;
		q) QEMUARG="$OPTARG" ;;
	esac
done
shift $((OPTIND -1))

[ "$GUEST" = "y" ] && guest "$@" || host "$@"
