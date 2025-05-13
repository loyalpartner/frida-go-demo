package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/frida/frida-go/frida"
)

var script = `
// Find the libXext library
const libXext = Process.findModuleByName("libXext.so");

if (libXext) {
    console.log("[*] Found libXext at " + libXext.base);
    
    // Try to find XShmCreateImage function
    const XShmCreateImage = Module.findExportByName("libXext.so", "XShmCreateImage");
    
    if (XShmCreateImage) {
        console.log("[*] Found XShmCreateImage at " + XShmCreateImage);
        
        Interceptor.attach(XShmCreateImage, {
            onEnter(args) {
                console.log("[*] XShmCreateImage called");
                this.display = args[0];
                this.visual = args[1];
                this.depth = args[2].toInt32();
                this.format = args[3].toInt32();
                console.log("[+] Display: " + this.display);
                console.log("[+] Visual: " + this.visual);
                console.log("[+] Depth: " + this.depth);
                console.log("[+] Format: " + this.format);
            },
            onLeave(retval) {
                console.log("[*] XShmCreateImage returned: " + retval);
                return retval;
            }
        });
    } else {
        console.log("[-] Failed to find XShmCreateImage");
    }
} else {
    console.log("[-] Failed to find libXext.so");
    
    // Try to find XShmCreateImage in all loaded modules
    console.log("[*] Searching for XShmCreateImage in all modules...");
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
        const XShmCreateImage = Module.findExportByName(modules[i].name, "XShmCreateImage");
        if (XShmCreateImage) {
            console.log("[+] Found XShmCreateImage in " + modules[i].name + " at " + XShmCreateImage);
            
            Interceptor.attach(XShmCreateImage, {
                onEnter(args) {
                    console.log("[*] XShmCreateImage called");
                    this.display = args[0];
                    this.visual = args[1];
                    this.depth = args[2].toInt32();
                    this.format = args[3].toInt32();
                    console.log("[+] Display: " + this.display);
                    console.log("[+] Visual: " + this.visual);
                    console.log("[+] Depth: " + this.depth);
                    console.log("[+] Format: " + this.format);
                },
                onLeave(retval) {
                    console.log("[*] XShmCreateImage returned: " + retval);
                    return retval;
                }
            });
            break;
        }
    }
}

// Keep the original hooks too
Interceptor.attach(Module.getExportByName(null, 'open'), {
	onEnter(args) {
		const what = args[0].readUtf8String();
		console.log("[*] open(" + what + ")");
	}
});
Interceptor.attach(Module.getExportByName(null, 'close'), {
	onEnter(args) {
		console.log("close called");
	}
});
`

func main() {
	mgr := frida.NewDeviceManager()

	devices, err := mgr.EnumerateDevices()
	if err != nil {
		panic(err)
	}

	for _, d := range devices {
		fmt.Println("[*] Found device with id:", d.ID())
	}

	localDev, err := mgr.LocalDevice()
	if err != nil {
		fmt.Println("Could not get local device: ", err)
		// Let's exit here because there is no point to do anything with nonexistent device
		os.Exit(1)
	}

	fmt.Println("[*] Chosen device: ", localDev.Name())

	if len(os.Args) < 2 {
		fmt.Println("Usage: ./main <pid>")
		os.Exit(1)
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Invalid PID:", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Attaching to process with PID: %d\n", pid)
	startTime := time.Now()
	session, err := localDev.Attach(pid, nil)
	if err != nil {
		fmt.Println("Error occurred attaching:", err)
		os.Exit(1)
	}
	elapsedTime := time.Since(startTime)
	fmt.Printf("[*] Attachment completed in: %v\n", elapsedTime)

	script, err := session.CreateScript(script)
	if err != nil {
		fmt.Println("Error occurred creating script:", err)
		os.Exit(1)
	}

	script.On("message", func(msg string) {
		fmt.Println("[*] Received", msg)
	})

	if err := script.Load(); err != nil {
		fmt.Println("Error loading script:", err)
		os.Exit(1)
	}

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
