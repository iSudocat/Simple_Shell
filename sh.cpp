#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include "hash.h"

using namespace std;

char *Busybox = (char *)"./busybox-1.32.0/busybox";

char **parse(string cmd)
{
    vector<string> command;
    stringstream input(cmd);
    string temp;
    while (getline(input, temp, ' '))
    {
        command.push_back(temp);
    }
    int args_num = command.size();
    char **args = (char **)malloc(sizeof(char *) * (args_num + 1));
    int index = 0;
    for (string c : command)
    {
        char *arg = new char[c.length() + 1];
        strcpy(arg, c.c_str());
        args[index++] = arg;
    }
    args[index++] = NULL;

    switch (hash_run_time(args[0]))
    {
        case "acpid"_hash:
        case "addgroup"_hash:
        case "adduser"_hash:
        case "adjtimex"_hash:
        case "arch"_hash:
        case "arp"_hash:
        case "arping"_hash:
        case "ash"_hash:
        case "awk"_hash:
        case "base64"_hash:
        case "basename"_hash:
        case "bc"_hash:
        case "beep"_hash:
        case "blkdiscard"_hash:
        case "blkid"_hash:
        case "blockdev"_hash:
        case "bootchartd"_hash:
        case "brctl"_hash:
        case "bunzip2"_hash:
        case "bzcat"_hash:
        case "bzip2"_hash:
        case "cal"_hash:
        case "cat"_hash:
        case "chat"_hash:
        case "chattr"_hash:
        case "chgrp"_hash:
        case "chmod"_hash:
        case "chown"_hash:
        case "chpasswd"_hash:
        case "chpst"_hash:
        case "chroot"_hash:
        case "chrt"_hash:
        case "chvt"_hash:
        case "cksum"_hash:
        case "clear"_hash:
        case "cmp"_hash:
        case "comm"_hash:
        case "conspy"_hash:
        case "cp"_hash:
        case "cpio"_hash:
        case "crond"_hash:
        case "crontab"_hash:
        case "cryptpw"_hash:
        case "cttyhack"_hash:
        case "cut"_hash:
        case "date"_hash:
        case "dc"_hash:
        case "dd"_hash:
        case "deallocvt"_hash:
        case "delgroup"_hash:
        case "deluser"_hash:
        case "depmod"_hash:
        case "devmem"_hash:
        case "df"_hash:
        case "dhcprelay"_hash:
        case "diff"_hash:
        case "dirname"_hash:
        case "dmesg"_hash:
        case "dnsd"_hash:
        case "dnsdomainname"_hash:
        case "dos2unix"_hash:
        case "dpkg"_hash:
        case "du"_hash:
        case "dumpkmap"_hash:
        case "dumpleases"_hash:
        case "echo"_hash:
        case "ed"_hash:
        case "egrep"_hash:
        case "eject"_hash:
        case "env"_hash:
        case "envdir"_hash:
        case "envuidgid"_hash:
        case "expand"_hash:
        case "expr"_hash:
        case "factor"_hash:
        case "fakeidentd"_hash:
        case "fallocate"_hash:
        case "fatattr"_hash:
        case "fbset"_hash:
        case "fbsplash"_hash:
        case "fdflush"_hash:
        case "fdformat"_hash:
        case "fdisk"_hash:
        case "fgconsole"_hash:
        case "fgrep"_hash:
        case "find"_hash:
        case "findfs"_hash:
        case "flock"_hash:
        case "fold"_hash:
        case "free"_hash:
        case "freeramdisk"_hash:
        case "fsck"_hash:
        case "fsfreeze"_hash:
        case "fstrim"_hash:
        case "fsync"_hash:
        case "ftpd"_hash:
        case "ftpget"_hash:
        case "ftpput"_hash:
        case "fuser"_hash:
        case "getopt"_hash:
        case "getty"_hash:
        case "grep"_hash:
        case "groups"_hash:
        case "gunzip"_hash:
        case "gzip"_hash:
        case "halt"_hash:
        case "hd"_hash:
        case "hdparm"_hash:
        case "head"_hash:
        case "hexdump"_hash:
        case "hexedit"_hash:
        case "hostid"_hash:
        case "hostname"_hash:
        case "httpd"_hash:
        case "hush"_hash:
        case "hwclock"_hash:
        case "i2cdetect"_hash:
        case "i2cdump"_hash:
        case "i2cget"_hash:
        case "i2cset"_hash:
        case "i2ctransfer"_hash:
        case "id"_hash:
        case "ifconfig"_hash:
        case "ifdown"_hash:
        case "ifenslave"_hash:
        case "ifplugd"_hash:
        case "ifup"_hash:
        case "inetd"_hash:
        case "init"_hash:
        case "insmod"_hash:
        case "install"_hash:
        case "ionice"_hash:
        case "iostat"_hash:
        case "ip"_hash:
        case "ipaddr"_hash:
        case "ipcalc"_hash:
        case "ipcrm"_hash:
        case "ipcs"_hash:
        case "iplink"_hash:
        case "ipneigh"_hash:
        case "iproute"_hash:
        case "iprule"_hash:
        case "iptunnel"_hash:
        case "kbd_mode"_hash:
        case "kill"_hash:
        case "killall"_hash:
        case "killall5"_hash:
        case "klogd"_hash:
        case "last"_hash:
        case "less"_hash:
        case "link"_hash:
        case "linux32"_hash:
        case "linux64"_hash:
        case "linuxrc"_hash:
        case "ln"_hash:
        case "loadfont"_hash:
        case "loadkmap"_hash:
        case "logger"_hash:
        case "login"_hash:
        case "logname"_hash:
        case "logread"_hash:
        case "losetup"_hash:
        case "lpd"_hash:
        case "lpq"_hash:
        case "lpr"_hash:
        case "ls"_hash:
        case "lsattr"_hash:
        case "lsmod"_hash:
        case "lsof"_hash:
        case "lspci"_hash:
        case "lsscsi"_hash:
        case "lsusb"_hash:
        case "lzcat"_hash:
        case "lzma"_hash:
        case "lzop"_hash:
        case "makedevs"_hash:
        case "makemime"_hash:
        case "man"_hash:
        case "md5sum"_hash:
        case "mdev"_hash:
        case "mesg"_hash:
        case "microcom"_hash:
        case "mim"_hash:
        case "mkdir"_hash:
        case "mkdosfs"_hash:
        case "mke2fs"_hash:
        case "mkfifo"_hash:
        case "mknod"_hash:
        case "mkpasswd"_hash:
        case "mkswap"_hash:
        case "mktemp"_hash:
        case "modinfo"_hash:
        case "modprobe"_hash:
        case "more"_hash:
        case "mount"_hash:
        case "mountpoint"_hash:
        case "mpstat"_hash:
        case "mt"_hash:
        case "mv"_hash:
        case "nameif"_hash:
        case "nanddump"_hash:
        case "nandwrite"_hash:
        case "nc"_hash:
        case "netstat"_hash:
        case "nice"_hash:
        case "nl"_hash:
        case "nmeter"_hash:
        case "nohup"_hash:
        case "nologin"_hash:
        case "nproc"_hash:
        case "nsenter"_hash:
        case "nslookup"_hash:
        case "ntpd"_hash:
        case "nuke"_hash:
        case "od"_hash:
        case "openvt"_hash:
        case "partprobe"_hash:
        case "passwd"_hash:
        case "paste"_hash:
        case "patch"_hash:
        case "pgrep"_hash:
        case "pidof"_hash:
        case "ping"_hash:
        case "ping6"_hash:
        case "pipe_progress"_hash:
        case "pivot_root"_hash:
        case "pkill"_hash:
        case "pmap"_hash:
        case "popmaildir"_hash:
        case "poweroff"_hash:
        case "powertop"_hash:
        case "printenv"_hash:
        case "printf"_hash:
        case "ps"_hash:
        case "pscan"_hash:
        case "pstree"_hash:
        case "pwd"_hash:
        case "pwdx"_hash:
        case "raidautorun"_hash:
        case "rdate"_hash:
        case "rdev"_hash:
        case "readahead"_hash:
        case "readlink"_hash:
        case "readprofile"_hash:
        case "realpath"_hash:
        case "reboot"_hash:
        case "reformime"_hash:
        case "renice"_hash:
        case "reset"_hash:
        case "resize"_hash:
        case "resume"_hash:
        case "rev"_hash:
        case "rm"_hash:
        case "rmdir"_hash:
        case "rmmod"_hash:
        case "route"_hash:
        case "rpm"_hash:
        case "rpm2cpio"_hash:
        case "rtcwake"_hash:
        case "runlevel"_hash:
        case "runsv"_hash:
        case "runsvdir"_hash:
        case "rx"_hash:
        case "script"_hash:
        case "scriptreplay"_hash:
        case "sed"_hash:
        case "sendmail"_hash:
        case "seq"_hash:
        case "setarch"_hash:
        case "setconsole"_hash:
        case "setfattr"_hash:
        case "setfont"_hash:
        case "setkeycodes"_hash:
        case "setlogcons"_hash:
        case "setpriv"_hash:
        case "setserial"_hash:
        case "setsid"_hash:
        case "setuidgid"_hash:
        case "sh"_hash:
        case "sha1sum"_hash:
        case "sha256sum"_hash:
        case "sha3sum"_hash:
        case "sha512sum"_hash:
        case "showkey"_hash:
        case "shred"_hash:
        case "shuf"_hash:
        case "slattach"_hash:
        case "sleep"_hash:
        case "smemcap"_hash:
        case "softlimit"_hash:
        case "sort"_hash:
        case "split"_hash:
        case "ssl_client"_hash:
        case "stat"_hash:
        case "strings"_hash:
        case "stty"_hash:
        case "su"_hash:
        case "sulogin"_hash:
        case "sum"_hash:
        case "sv"_hash:
        case "svc"_hash:
        case "svlogd"_hash:
        case "svok"_hash:
        case "swapoff"_hash:
        case "swapon"_hash:
        case "switch_root"_hash:
        case "sync"_hash:
        case "sysctl"_hash:
        case "syslogd"_hash:
        case "tac"_hash:
        case "tail"_hash:
        case "tar"_hash:
        case "taskset"_hash:
        case "tc"_hash:
        case "tcpsvd"_hash:
        case "tee"_hash:
        case "telnet"_hash:
        case "telnetd"_hash:
        case "test"_hash:
        case "tftp"_hash:
        case "tftpd"_hash:
        case "time"_hash:
        case "timeout"_hash:
        case "top"_hash:
        case "touch"_hash:
        case "tr"_hash:
        case "traceroute"_hash:
        case "traceroute6"_hash:
        case "truncate"_hash:
        case "ts"_hash:
        case "tty"_hash:
        case "ttysize"_hash:
        case "tunctl"_hash:
        case "ubiattach"_hash:
        case "ubidetach"_hash:
        case "ubimkvol"_hash:
        case "ubirename"_hash:
        case "ubirmvol"_hash:
        case "ubirsvol"_hash:
        case "ubiupdatevol"_hash:
        case "udhcpc"_hash:
        case "udhcpc6"_hash:
        case "udhcpd"_hash:
        case "udpsvd"_hash:
        case "uevent"_hash:
        case "umount"_hash:
        case "uname"_hash:
        case "unexpand"_hash:
        case "uniq"_hash:
        case "unix2dos"_hash:
        case "unlink"_hash:
        case "unlzma"_hash:
        case "unshare"_hash:
        case "unxz"_hash:
        case "unzip"_hash:
        case "uptime"_hash:
        case "users"_hash:
        case "usleep"_hash:
        case "uudecode"_hash:
        case "uuencode"_hash:
        case "vconfig"_hash:
        case "vi"_hash:
        case "vlock"_hash:
        case "volname"_hash:
        case "w"_hash:
        case "wall"_hash:
        case "watch"_hash:
        case "watchdog"_hash:
        case "wc"_hash:
        case "wget"_hash:
        case "which"_hash:
        case "who"_hash:
        case "whoami"_hash:
        case "whois"_hash:
        case "xargs"_hash:
        case "xxd"_hash:
        case "xz"_hash:
        case "xzcat"_hash:
        case "yes"_hash:
        case "zcat"_hash:
        case "zcip"_hash:
            return args;
        default:
            return nullptr;
    }

}

void execute(char **args)
{
    if(args == nullptr){
        cout << "Error: Command not found" << endl;
        return;
    }
    pid_t child_pid = fork();
    int status;
    if (child_pid < 0)
    {
        cout << "Error: fork failed" << endl;
        return;
    }
    else if (child_pid == 0)
    {
        char *bpath = Busybox;
        if (execv(bpath, args) < 0)
        {
            cout << "Error: execv failed" << endl;
            return;
        }
    }
    else
    {
        waitpid(child_pid, &status, 0);
    }
}

int main()
{
    while (true)
    {
        cout << "Sudocat's Shell $";
        string input;
        getline(cin, input);
        char **command = parse(input);
        execute(command);
    }

    return 0;
}