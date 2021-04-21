package main

import (
    "bufio"
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "fmt"
    "os"
    "regexp"
)

var hook_name string = "zzm_tcp_connect"

func Exists(path string) bool {
    _, err := os.Stat(path)
    if err != nil {
        if os.IsExist(err) {
            return true
        }
        return false
    }
    return true
}

func writeFile(path string, content string, priv int) {
    f, err := os.OpenFile(path, priv, 0644)
    if err != nil {
        fmt.Println("文件打开失败", err)
    }
    defer f.Close()
    f.WriteString(content)
}

func enableTrace() {
    // 删除之前的自定义hook函数
    kprobe_events := "/sys/kernel/debug/tracing/kprobe_events"
    writeFile(kprobe_events, "\n-:"+hook_name, os.O_WRONLY|os.O_APPEND)
    // 新建hook函数
    writeFile(kprobe_events, fmt.Sprintf("\np:kprobes/%s tcp_connect saddr=+4(%%di):u32 daddr=+0(%%di):u32 sport=+14(%%di):u16 dport=+12(%%di):u16", hook_name), os.O_WRONLY|os.O_APPEND)
    // 新建实例
    if !Exists("/sys/kernel/debug/tracing/instances/" + hook_name) {
        os.Mkdir("/sys/kernel/debug/tracing/instances/"+hook_name, os.ModePerm)
    }
    // 开启trace
    writeFile(fmt.Sprintf("/sys/kernel/debug/tracing/instances/%s/events/kprobes/enable", hook_name), "1", os.O_WRONLY)
}

func decodeLittleHex(s string) uint32 {
    var decode_s uint32
    byte_s, _ := hex.DecodeString(s)
    buffer_s := bytes.NewReader(byte_s)
    binary.Read(buffer_s, binary.LittleEndian, &decode_s)
    return decode_s
}

func ipConv(s string) string {
    ip := decodeLittleHex(s)
    return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func parseLine(line string) {
    pid_pattern := regexp.MustCompile(`-(\d{1,5})\s+\[`)
    info_pattern := regexp.MustCompile(`\) saddr=([0-9a-z]+) daddr=([0-9a-z]+) sport=([0-9a-z]+) dport=([0-9a-z]+)`)

    pid := pid_pattern.FindStringSubmatch(line)[1]
    saddr := info_pattern.FindStringSubmatch(line)[1]
    daddr := info_pattern.FindStringSubmatch(line)[2]
    sport := info_pattern.FindStringSubmatch(line)[3] + "0000"
    dport := info_pattern.FindStringSubmatch(line)[4] + "0000"
    fmt.Printf("进程ID: %s\n源IP: %s\n源端口: %d\n目的IP: %s\n目的端口: %d\n", pid, ipConv(saddr), decodeLittleHex(sport), ipConv(daddr), decodeLittleHex(dport))
}

func readLog() {
    f, err := os.Open(fmt.Sprintf("/sys/kernel/debug/tracing/instances/%s/trace_pipe", hook_name))
    if err != nil {
        fmt.Println("Open named pipe file error:", err)
    }
    defer f.Close()

    reader := bufio.NewReader(f)

    for {
        line, err := reader.ReadBytes('\n')
        if err == nil {
            parseLine(string(line))
        }
    }
}

func main() {
    enableTrace()
    readLog()
}