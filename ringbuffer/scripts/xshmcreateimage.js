// 寻找包含 libXext 的库，考虑版本号后缀
console.log("[*] Searching for libraries containing libXext");

// 首先尝试直接查找标准名称
let libXext = Process.findModuleByName("libXext.so");

// 如果没找到，尝试查找可能带有版本号的库
if (!libXext) {
  console.log("[*] Trying to find libXext with version suffix");
  const modules = Process.enumerateModules();
  for (let i = 0; i < modules.length; i++) {
    if (modules[i].name.includes("libXext")) {
      libXext = modules[i];
      console.log("[+] Found version with suffix: " + modules[i].name);
      break;
    }
  }
}

if (!libXext) {
  console.log("[-] Could not find libXext library");
  return;
}

console.log(
  "[*] Found libXext at " + libXext.base + " (name: " + libXext.name + ")",
);

// 在找到的库中查找 XShmCreateImage 函数
const XShmCreateImage = Module.findExportByName(
  libXext.name,
  "XShmCreateImage",
);

if (XShmCreateImage) {
  console.log("[*] Found XShmCreateImage at " + XShmCreateImage);

  Interceptor.attach(XShmCreateImage, {
    onEnter(args) {
      console.log("[*] XShmCreateImage called");
      console.log("[*] Holding process for observation...");
      Thread.sleep(5); // 睡眠5秒，给足够观察时间
    },
    onLeave(retval) {
      console.log("[*] XShmCreateImage returned: " + retval);
      return retval;
    },
  });
} else {
  console.log("[-] Failed to find XShmCreateImage in " + libXext.name);
}
