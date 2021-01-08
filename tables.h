#pragma once

namespace Details {
    namespace Tables {
        map<WORD, const char*> machine{
            make_pair(0X0000,"未知"),
            make_pair(0x0001,"目标主机(TARGET_HOST?)"),
            make_pair(0x014c,"I386"),
            make_pair(0x0160,"MIPS(大端序)"),
            make_pair(0x0162,"MIPS(小端序)"),
            make_pair(0x0166,"MIPS(小端序)"),
            make_pair(0x0168,"MIPS(小端序)"),
            make_pair(0x0169,"MIPS(小端序)WCE v2"),
            make_pair(0x0184,"Alpha_AXP"),
            make_pair(0x01a2,"SH3(小端序)"),
            make_pair(0x01a3,"SH3DSP"),
            make_pair(0x01a4,"SH3E(小端序)"),
            make_pair(0x01a6,"SH4(小端序)"),
            make_pair(0x01a8,"SH5"),
            make_pair(0x01c0,"ARM(小端序)"),
            make_pair(0x01c2,"ARM Thumb/Thumb-2(小端序)"),
            make_pair(0x01c4,"ARM Thumb-2(小端序)"),
            make_pair(0x01d3,"AM33"),
            make_pair(0X01F0,"Power PC(小端序)"),
            make_pair(0x01f1,"Power PC FP"),
            make_pair(0x0200,"X86_64(x64)"),
            make_pair(0x0266,"MIPS16"),
            make_pair(0x0284,"ALPHA64"),
            make_pair(0x0366,"MIPSFPU"),
            make_pair(0x0466,"MIPSFPU16"),
            make_pair(0x0284,"AXP64"),
            make_pair(0x0520,"TRICORE"),
            make_pair(0x0CEF,"CEF"),
            make_pair(0x0EBC,"EFI字节码"),
            make_pair(0x8664,"AMD64(K8)"),
            make_pair(0x9041,"M32R(小端序)"),
            make_pair(0xAA64,"ARM64(小端序)"),
            make_pair(0XC0EE,"CEE"),
        };
        map<USHORT, const char*> characteristics{
            make_pair(0x0001,"重定位信息已从文件剥离"),
            make_pair(0x0002,"文件为可执行程序"),
            make_pair(0x0004,"行号已从文件剥离"),
            make_pair(0x0008,"本地符号已从文件剥离"),
            make_pair(0x0010,"强力修整工作装置(?)"),
            make_pair(0x0020,"程序可处理大于2GB的地址"),
            make_pair(0x0080,"机器字节已被反转"),
            make_pair(0x0100,"32位机器"),
            make_pair(0x0200,"调试信息已从文件剥离至.DBG后缀的文件"),
            make_pair(0x0400,"如果程序在可移动媒体上,复制并从交换文件运行。"),
            make_pair(0x0800,"如果程序在网络上，复制并从交换文件运行。"),
            make_pair(0x1000,"文件为系统程序"),
            make_pair(0x2000,"文件为DLL"),
            make_pair(0x4000,"文件只应运行在向上的机器上(?)"),
            make_pair(0x8000,"机器每个字中的字节已被反转(?)"),
        };
        map<WORD, const char*> subsystem{
            make_pair(0,"未知子系统"),
            make_pair(1,"程序无需子系统"),
            make_pair(2,"程序在Windows图形用户接口子系统中运行"),
            make_pair(3,"程序在Windows角色子系统(?)中运行"),
            make_pair(5,"程序在OS/2角色子系统(?)中运行"),
            make_pair(7,"程序在POSIX角色子系统(?)中运行"),
            make_pair(8,"程序是一个本地Windows 90/95/98驱动"),
            make_pair(9,"程序在Windows CE子系统中运行"),
            make_pair(10,"EFI应用"),
            make_pair(11,"EFI引导服务驱动"),
            make_pair(12,"EFI运行时驱动"),
            make_pair(13,"EFI-ROM"),
            make_pair(14,"Xbox"),
            make_pair(16,"Windows引导应用"),
            make_pair(17,"Xbox代码CATALOG"),
        };
        map<WORD, const char*> dllcharacteristics{
            make_pair(0x0020,"DLL可以处离高熵(?)的64位虚拟地址空间"),
            make_pair(0x0040,"DLL可被移动"),
            make_pair(0x0080,"代码完整的DLL"),
            make_pair(0x0100,"DLL与NX兼容"),
            make_pair(0x0200,"Image understands isolation and doesn't want it"),
            make_pair(0x0400,"DLL不使用SSH,任何SE句柄都不能驻留在此映像中"),
            make_pair(0x0800,"不要绑定该DLL"),
            make_pair(0x1000,"DLL应在应用容器中执行"),
            make_pair(0x2000,"驱动使用WDM模型"),
            make_pair(0x4000,"DLL支持控制流保护"),
            make_pair(0x8000,"Terminal Server Aware"),
        };
        map<DWORD, const char*> characteristics_s{
            make_pair(0x00000008,"TYPE_NO_PAD"),
            make_pair(0x00000020,"包含代码"),
            make_pair(0x00000040,"包含已初始化的数据"),
            make_pair(0x00000080,"包含未初始化的数据"),
            make_pair(0x00000100,"LNK_OTHER"),
            make_pair(0x00000200,"包含注释或其他类型的信息"),
            make_pair(0x00000800,"上下文将不会成为程序的一部分"),
            make_pair(0x00001000,"包含comdat(COM数据?)"),
            make_pair(0x00004000,"重置TLB项中的投机异常处理位"),
            make_pair(0x00008000,"上下文可以相对GP访问,数据指针使用FAR模式"),
            make_pair(0x00020000,"PURGEABLE,16位内存"),
            make_pair(0x00040000,"内存已设定"),
            make_pair(0x00080000,"内存超前加载(?)"),
            make_pair(0x01000000,"包含扩展的重定位(?)"),
            make_pair(0x02000000,"可丢弃"),
            make_pair(0x04000000,"不可使用cache缓存"),
            make_pair(0x08000000,"不可分页"),
            make_pair(0x10000000,"可共享"),
            make_pair(0x20000000,"可执行"),
            make_pair(0x40000000,"可读"),
            make_pair(0x80000000,"可写"),
        };
    }
    string machine(WORD key) {
        auto value = Tables::machine[key];
        return (value ? value : "未知");
    }
    string characteristics(USHORT key) {
        string value = "";
        for (auto& item : Tables::characteristics)
            if (key & item.first)
                value += item.second, value += ",";
        return value.substr(0, value.size() - 1);
    }
    string subsystem(WORD key) {
        auto value = Tables::subsystem[key];
        return (value ? value : "未知子系统");
    }
    string dllcharacteristics(WORD key) {
        string value = "";
        for (auto& item : Tables::dllcharacteristics)
            if (key & item.first)
                value += item.second, value += ",";
        return value.substr(0, value.size() - 1);
    }
    string characteristics_s(DWORD key) {
        map<DWORD, const char*> cases{
            make_pair(0x00100000,"以1字节方式对齐"),
            make_pair(0x00200000,"以2字节方式对齐"),
            make_pair(0x00300000,"以4字节方式对齐"),
            make_pair(0x00400000,"以8字节方式对齐"),
            make_pair(0x00500000,"以16字节方式对齐"),
            make_pair(0x00600000,"以32字节方式对齐"),
            make_pair(0x00700000,"以64字节方式对齐"),
            make_pair(0x00800000,"以128字节方式对齐"),
            make_pair(0x00900000,"以256字节方式对齐"),
            make_pair(0x00A00000,"以512字节方式对齐"),
            make_pair(0x00B00000,"以1024字节方式对齐"),
            make_pair(0x00C00000,"以2048字节方式对齐"),
            make_pair(0x00D00000,"以4096字节方式对齐"),
            make_pair(0x00E00000,"以8192字节方式对齐"),
        };
        string value = "";
        for (auto& item : Tables::characteristics_s)
            if (key & item.first)
                value += item.second, value += ",";
        key &= 0x00F00000;
        if (key != 0)
            value = value + cases[key] + ",";
        return value.substr(0, value.size() - 1);
    }
}