package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"io/ioutil"
	"time"
	"strconv"
	"strings"
	"encoding/json"
)

var fdch chan int

func init() {
	fdch = make(chan int, 10000)
}


const (
	// <linux/connector.h>
	CN_IDX_PROC = 0x1
	CN_VAL_PROC = 0x1

	// <linux/cn_proc.h>
	PROC_CN_GET_FEATURES = 0
	PROC_CN_MCAST_LISTEN = 1
	PROC_CN_MCAST_IGNORE = 2

	PROC_EVENT_NONE   = 0x00000000
	PROC_EVENT_FORK   = 0x00000001
	PROC_EVENT_EXEC   = 0x00000002
	PROC_EVENT_UID    = 0x00000004
	PROC_EVENT_GID    = 0x00000040
	PROC_EVENT_SID    = 0x00000080
	PROC_EVENT_PTRACE = 0x00000100
	PROC_EVENT_COMM   = 0x00000200
	PROC_EVENT_NS     = 0x00000400

	PROC_EVENT_COREDUMP = 0x40000000
	PROC_EVENT_EXIT     = 0x80000000
)

var (
	byteOrder = binary.LittleEndian
	seq uint32
)

type cbId struct {
	Idx uint32
	Val uint32
}

// linux/connector.h: struct cb_msg
/*
	发送的结构体定义
*/
type cnMsg struct {
	Id    cbId
	Seq   uint32
	Ack   uint32
	Len   uint16
	Flags uint16
}

type procEventHeader struct {
	What      uint32
	Cpu       uint32
	Timestamp uint64
}

type execProcEvent struct {
	ProcessPid  uint32
	ProcessTgid uint32
}

/*
	从pid中读取数据
*/

func receive(sock int) {
	buf := make([]byte, syscall.Getpagesize())

	for {
		nr, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			fmt.Printf("recvfrom failed: %v\n", err)
			os.Exit(1)
		}
		if nr < syscall.NLMSG_HDRLEN {
			continue
		}

		msgs, _ := syscall.ParseNetlinkMessage(buf[:nr])
		for _, m := range msgs {
			if m.Header.Type == syscall.NLMSG_DONE {
				handleProcEvent(m.Data)
			}
		}
	}
}

// 读取进程文件内容
func readFile(path string) string {
	var content string
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	bytesf, err := ioutil.ReadAll(f)
	for _,v := range bytesf {
		if v == 0 {
			content = content + " "
		} else {
			content = content + string(v)
		}
	}
	if err != nil {
		return ""
	}
	return content
}

func readProc(pid string) bool {
	cmdline := readFile("/proc/" + pid + "/cmdline")
	ppid := "1"
	if pid == "1" ||  len(readFile("/proc/" + pid + "/stat")) >= 4 {
		ppid = strings.Fields(readFile("/proc/" + pid + "/stat"))[3]
	}
	pcmdline := readFile("/proc/" + ppid + "/cmdline")

	cur_pid := pid
	var chain []map[string]string
	chain = append(chain, map[string]string{
		pid: cmdline,
	})

	for {
		if cur_pid == "1" ||  len(readFile("/proc/" + cur_pid + "/stat"))<4 {
			break
		}
		cur_pid = strings.Fields(readFile("/proc/" + cur_pid + "/stat"))[3]
		cur_cmd := readFile("/proc/" + cur_pid + "/cmdline")
		chain = append(chain, map[string]string{
			cur_pid: cur_cmd,
		})
	}

	fmt.Println("\033[;32m[时间]\033[0m : " + time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("\033[;32m[pid]\033[0m : " + pid)
	fmt.Println("\033[;32m[cmd]\033[0m : " + cmdline)
	fmt.Println("\033[;32m[ppid]\033[0m : " + ppid)
	fmt.Println("\033[;32m[pcmdline]\033[0m : " + pcmdline)
	e,_ := json.MarshalIndent(chain,"","\t")
	fmt.Println("\033[;32m[进程链]\033[0m : \n" + string(e))
	fmt.Println("");
	return true
}

func getProc() {
	go func() {
		for {
			fd, ok := <- fdch
			if ok{
				readProc(strconv.Itoa(fd))
			}
		}
	}()
}

/*
	处理返回来的消息进程
*/
func handleProcEvent(data []byte) {
	buf := bytes.NewBuffer(data)
	msg := &cnMsg{}
	hdr := &procEventHeader{}

	binary.Read(buf, byteOrder, msg)
	binary.Read(buf, byteOrder, hdr)

	switch hdr.What {
	case PROC_EVENT_NONE:
		fmt.Printf("none: flags=%v\n", msg.Flags)

	case PROC_EVENT_FORK:

	case PROC_EVENT_EXEC:
		event := &execProcEvent{}
		binary.Read(buf, byteOrder, event)
		pid := int(event.ProcessTgid)

		fdch <- pid

	case PROC_EVENT_NS:
	case PROC_EVENT_EXIT:
	case PROC_EVENT_UID:
	case PROC_EVENT_GID:
	case PROC_EVENT_SID:
	case PROC_EVENT_PTRACE:
	case PROC_EVENT_COMM:
	case PROC_EVENT_COREDUMP:

	default:
		fmt.Printf("???: what=%x\n", hdr.What)
	}
}

func main() {
	getProc()

	sock, err := syscall.Socket(
		syscall.AF_NETLINK, // 确定通信的特性，包括地址格式。
		syscall.SOCK_DGRAM, // 确定套接字的类型，进一步确定通信特征，也可以写SOCK_RAW。
		syscall.NETLINK_CONNECTOR) // 协议选择 内核链接器
	if err != nil {
		fmt.Printf("socket failed: %v\n", err)
		os.Exit(1)
	}

	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: CN_IDX_PROC,
	}

	err = syscall.Bind(sock, addr)
	if err != nil {
		fmt.Printf("bind failed: %v\n", err)
		os.Exit(1)
	}

	receive(sock)

}