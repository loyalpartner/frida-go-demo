//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/frida/frida-go/frida"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event bpf ringbuffer.c -- -I../headers

// setupSignalHandler 设置信号处理，返回上下文和取消函数
func setupSignalHandler() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-stopper
		log.Printf("收到信号 %v，准备退出...", sig)
		cancel()
	}()

	return ctx, cancel
}

// setupEBPF 设置 eBPF 程序和映射
func setupEBPF() (*bpfObjects, *perf.Reader, []link.Link, error) {
	// 允许当前进程为 eBPF 资源锁定内存
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("移除内存锁限制失败: %w", err)
	}

	// 加载预编译的 eBPF 程序和映射到内核
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("加载 eBPF 对象失败: %w", err)
	}

	// 保存所有需要关闭的链接
	var links []link.Link

	// 设置 kprobe
	kp, err := link.Kprobe("do_exit", objs.KprobeDoExit, nil)
	if err != nil {
		objs.Close()
		return nil, nil, nil, fmt.Errorf("设置 kprobe do_exit 失败: %w", err)
	}
	links = append(links, kp)

	// 设置 tracepoint
	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.TracepointSchedProcessExec, nil)
	if err != nil {
		objs.Close()
		for _, link := range links {
			link.Close()
		}
		return nil, nil, nil, fmt.Errorf("设置 tracepoint sched_process_exec 失败: %w", err)
	}
	links = append(links, tp)

	// 打开 perf 读取器
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		objs.Close()
		for _, link := range links {
			link.Close()
		}
		return nil, nil, nil, fmt.Errorf("打开 perf 读取器失败: %w", err)
	}

	return &objs, rd, links, nil
}

func main() {
	// 配置日志
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.Println("eBPF 进程监控和 Frida 注入示例启动")

	// 设置信号处理
	ctx, cancel := setupSignalHandler()
	defer cancel()

	// 设置 eBPF
	objs, rd, links, err := setupEBPF()
	if err != nil {
		log.Fatal(err)
	}

	// 确保清理资源
	defer func() {
		rd.Close()
		for _, link := range links {
			link.Close()
		}
		objs.Close()
	}()

	// 初始化 Frida
	mgr := frida.NewDeviceManager()
	devices, err := mgr.EnumerateDevices()
	if err != nil {
		log.Fatalf("枚举 Frida 设备失败: %v", err)
	}

	log.Printf("发现 %d 个 Frida 设备", len(devices))
	for _, d := range devices {
		log.Printf("[*] Found device with id: %s", d.ID())
	}

	localDev, err := mgr.LocalDevice()
	if err != nil {
		log.Fatalf("无法获取本地 Frida 设备: %v", err)
	}
	log.Printf("[*] 使用设备: %s", localDev.Name())

	// 类型断言转换为所需类型
	localDevPtr := localDev.(*frida.Device)

	// 启动事件处理循环
	log.Println("等待事件中...")
	go processEvents(ctx, rd, localDevPtr)

	// 等待上下文取消
	<-ctx.Done()
	log.Println("程序正在退出...")
}

// handleFridaInjection attaches to a process and injects the Frida script
func handleFridaInjection(localDev *frida.Device, pid int, eventType uint8) {
	fmt.Println("[*] Event details:", eventType)
	fmt.Printf("[*] Attaching to process with PID: %d\n", pid)

	startTime := time.Now()
	session, err := localDev.Attach(pid, nil)
	if err != nil {
		fmt.Println("Error occurred attaching:", err)
		return
	}
	elapsedTime := time.Since(startTime)
	fmt.Printf("[*] Attachment completed in: %v\n", elapsedTime)

	// 使用来自script.go中的脚本
	scriptInstance, err := session.CreateScript(XShmCreateImageScript)
	if err != nil {
		fmt.Println("Error occurred creating script:", err)
		return
	}

	scriptInstance.On("message", func(msg string) {
		fmt.Println("[*] Received", msg)
	})

	if err := scriptInstance.Load(); err != nil {
		fmt.Println("Error loading script:", err)
		return
	}

	// 脚本加载后继续运行一段时间以确保捕获到函数调用
	fmt.Println("[*] Script loaded successfully, monitoring for events...")

	// 等待一段时间给目标进程和脚本时间执行
	// 30秒后自动结束，避免长时间阻塞
	timer := time.NewTimer(30 * time.Second)
	done := make(chan bool)

	go func() {
		session.On("detached", func(reason int, crash interface{}) {
			fmt.Printf("[*] Session detached with reason: %d\n", reason)
			close(done)
		})
	}()

	select {
	case <-done:
		fmt.Println("[*] Target process completed")
	case <-timer.C:
		fmt.Println("[*] Monitoring timeout reached")
	}
}

// processEvents 持续从 ringbuffer 读取事件并处理
func processEvents(ctx context.Context, rd *perf.Reader, localDev *frida.Device) {
	var event bpfEvent

	// 监控的目标程序列表
	targetPrograms := []string{
		"top", "scrot", "grim", "deepin-screen-recorder",
	}

	for {
		// 检查上下文是否取消
		select {
		case <-ctx.Done():
			return
		default:
			// 继续执行
		}

		// 尝试从 perf 缓冲区读取记录
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Perf buffer 已关闭，退出事件处理...")
				return
			}
			log.Printf("读取 perf buffer: %s", err)
			continue
		}

		// 解析事件数据到 bpfEvent 结构
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("解析事件失败: %s", err)
			continue
		}

		// 获取进程名称
		comm := unix.ByteSliceToString(event.Comm[:])

		// 如果是目标程序执行事件，则注入 Frida 脚本
		if slices.Contains(targetPrograms, comm) && event.Type == 0 {
			// 使用 goroutine 避免阻塞事件循环
			go func(pid int, eType uint8) {
				// 立即注入，尽量在进程初始化阶段就捕获
				handleFridaInjection(localDev, pid, eType)
			}(int(event.Pid), event.Type)
		}
	}
}
