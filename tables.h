#pragma once

namespace Details {
    namespace Tables {
        map<WORD, const char*> machine{
            make_pair(0X0000,"δ֪"),
            make_pair(0x0001,"Ŀ������(TARGET_HOST?)"),
            make_pair(0x014c,"I386"),
            make_pair(0x0160,"MIPS(�����)"),
            make_pair(0x0162,"MIPS(С����)"),
            make_pair(0x0166,"MIPS(С����)"),
            make_pair(0x0168,"MIPS(С����)"),
            make_pair(0x0169,"MIPS(С����)WCE v2"),
            make_pair(0x0184,"Alpha_AXP"),
            make_pair(0x01a2,"SH3(С����)"),
            make_pair(0x01a3,"SH3DSP"),
            make_pair(0x01a4,"SH3E(С����)"),
            make_pair(0x01a6,"SH4(С����)"),
            make_pair(0x01a8,"SH5"),
            make_pair(0x01c0,"ARM(С����)"),
            make_pair(0x01c2,"ARM Thumb/Thumb-2(С����)"),
            make_pair(0x01c4,"ARM Thumb-2(С����)"),
            make_pair(0x01d3,"AM33"),
            make_pair(0X01F0,"Power PC(С����)"),
            make_pair(0x01f1,"Power PC FP"),
            make_pair(0x0200,"X86_64(x64)"),
            make_pair(0x0266,"MIPS16"),
            make_pair(0x0284,"ALPHA64"),
            make_pair(0x0366,"MIPSFPU"),
            make_pair(0x0466,"MIPSFPU16"),
            make_pair(0x0284,"AXP64"),
            make_pair(0x0520,"TRICORE"),
            make_pair(0x0CEF,"CEF"),
            make_pair(0x0EBC,"EFI�ֽ���"),
            make_pair(0x8664,"AMD64(K8)"),
            make_pair(0x9041,"M32R(С����)"),
            make_pair(0xAA64,"ARM64(С����)"),
            make_pair(0XC0EE,"CEE"),
        };
        map<USHORT, const char*> characteristics{
            make_pair(0x0001,"�ض�λ��Ϣ�Ѵ��ļ�����"),
            make_pair(0x0002,"�ļ�Ϊ��ִ�г���"),
            make_pair(0x0004,"�к��Ѵ��ļ�����"),
            make_pair(0x0008,"���ط����Ѵ��ļ�����"),
            make_pair(0x0010,"ǿ����������װ��(?)"),
            make_pair(0x0020,"����ɴ������2GB�ĵ�ַ"),
            make_pair(0x0080,"�����ֽ��ѱ���ת"),
            make_pair(0x0100,"32λ����"),
            make_pair(0x0200,"������Ϣ�Ѵ��ļ�������.DBG��׺���ļ�"),
            make_pair(0x0400,"��������ڿ��ƶ�ý����,���Ʋ��ӽ����ļ����С�"),
            make_pair(0x0800,"��������������ϣ����Ʋ��ӽ����ļ����С�"),
            make_pair(0x1000,"�ļ�Ϊϵͳ����"),
            make_pair(0x2000,"�ļ�ΪDLL"),
            make_pair(0x4000,"�ļ�ֻӦ���������ϵĻ�����(?)"),
            make_pair(0x8000,"����ÿ�����е��ֽ��ѱ���ת(?)"),
        };
        map<WORD, const char*> subsystem{
            make_pair(0,"δ֪��ϵͳ"),
            make_pair(1,"����������ϵͳ"),
            make_pair(2,"������Windowsͼ���û��ӿ���ϵͳ������"),
            make_pair(3,"������Windows��ɫ��ϵͳ(?)������"),
            make_pair(5,"������OS/2��ɫ��ϵͳ(?)������"),
            make_pair(7,"������POSIX��ɫ��ϵͳ(?)������"),
            make_pair(8,"������һ������Windows 90/95/98����"),
            make_pair(9,"������Windows CE��ϵͳ������"),
            make_pair(10,"EFIӦ��"),
            make_pair(11,"EFI������������"),
            make_pair(12,"EFI����ʱ����"),
            make_pair(13,"EFI-ROM"),
            make_pair(14,"Xbox"),
            make_pair(16,"Windows����Ӧ��"),
            make_pair(17,"Xbox����CATALOG"),
        };
        map<WORD, const char*> dllcharacteristics{
            make_pair(0x0020,"DLL���Դ������(?)��64λ�����ַ�ռ�"),
            make_pair(0x0040,"DLL�ɱ��ƶ�"),
            make_pair(0x0080,"����������DLL"),
            make_pair(0x0100,"DLL��NX����"),
            make_pair(0x0200,"Image understands isolation and doesn't want it"),
            make_pair(0x0400,"DLL��ʹ��SSH,�κ�SE���������פ���ڴ�ӳ����"),
            make_pair(0x0800,"��Ҫ�󶨸�DLL"),
            make_pair(0x1000,"DLLӦ��Ӧ��������ִ��"),
            make_pair(0x2000,"����ʹ��WDMģ��"),
            make_pair(0x4000,"DLL֧�ֿ���������"),
            make_pair(0x8000,"Terminal Server Aware"),
        };
        map<DWORD, const char*> characteristics_s{
            make_pair(0x00000008,"TYPE_NO_PAD"),
            make_pair(0x00000020,"��������"),
            make_pair(0x00000040,"�����ѳ�ʼ��������"),
            make_pair(0x00000080,"����δ��ʼ��������"),
            make_pair(0x00000100,"LNK_OTHER"),
            make_pair(0x00000200,"����ע�ͻ��������͵���Ϣ"),
            make_pair(0x00000800,"�����Ľ������Ϊ�����һ����"),
            make_pair(0x00001000,"����comdat(COM����?)"),
            make_pair(0x00004000,"����TLB���е�Ͷ���쳣����λ"),
            make_pair(0x00008000,"�����Ŀ������GP����,����ָ��ʹ��FARģʽ"),
            make_pair(0x00020000,"PURGEABLE,16λ�ڴ�"),
            make_pair(0x00040000,"�ڴ����趨"),
            make_pair(0x00080000,"�ڴ泬ǰ����(?)"),
            make_pair(0x01000000,"������չ���ض�λ(?)"),
            make_pair(0x02000000,"�ɶ���"),
            make_pair(0x04000000,"����ʹ��cache����"),
            make_pair(0x08000000,"���ɷ�ҳ"),
            make_pair(0x10000000,"�ɹ���"),
            make_pair(0x20000000,"��ִ��"),
            make_pair(0x40000000,"�ɶ�"),
            make_pair(0x80000000,"��д"),
        };
    }
    string machine(WORD key) {
        auto value = Tables::machine[key];
        return (value ? value : "δ֪");
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
        return (value ? value : "δ֪��ϵͳ");
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
            make_pair(0x00100000,"��1�ֽڷ�ʽ����"),
            make_pair(0x00200000,"��2�ֽڷ�ʽ����"),
            make_pair(0x00300000,"��4�ֽڷ�ʽ����"),
            make_pair(0x00400000,"��8�ֽڷ�ʽ����"),
            make_pair(0x00500000,"��16�ֽڷ�ʽ����"),
            make_pair(0x00600000,"��32�ֽڷ�ʽ����"),
            make_pair(0x00700000,"��64�ֽڷ�ʽ����"),
            make_pair(0x00800000,"��128�ֽڷ�ʽ����"),
            make_pair(0x00900000,"��256�ֽڷ�ʽ����"),
            make_pair(0x00A00000,"��512�ֽڷ�ʽ����"),
            make_pair(0x00B00000,"��1024�ֽڷ�ʽ����"),
            make_pair(0x00C00000,"��2048�ֽڷ�ʽ����"),
            make_pair(0x00D00000,"��4096�ֽڷ�ʽ����"),
            make_pair(0x00E00000,"��8192�ֽڷ�ʽ����"),
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