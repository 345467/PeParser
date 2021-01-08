#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include <fstream>
#include <string>
#include <time.h>
#include <map>
using namespace std;

#include "tables.h"

namespace Details {
    template<class _St,typename _Dt>
    void Read(_St &file, _Dt* ptr) {
        if (!file.good())
            exit(-1);
        file.read((char*)ptr, sizeof(_Dt));
    }

    template<typename _Dt,typename _Et = std::exception_ptr>
    class __Optional {
        union {
            _Dt d;
            _Et e;
        }v;
        bool has_data;
    public:
        __Optional(_Dt d) :has_data(true) {
            v.d = d;
        }
        __Optional(_Et e) :has_data(false) {
            v.e = e;
        }
        ~__Optional<_Dt, _Et>() {

        }
        template<class Exception, typename... _At>
        static exception_ptr newException(_At... args) {
            try {
                throw Exception(args...);
            }
            catch (const Exception& e) {
                return (exception_ptr)current_exception();
            }
        }
        template<typename d, typename e = std::exception_ptr>
        static __Optional<d, e> success(d in) {
            return __Optional<d, e>(in);
        }
        template<typename d, typename e = std::exception_ptr>
        static __Optional<d, e> fail(e in) {
            return __Optional<d, e>(in);
        }
        _Dt data() {
            if (has_data)
                return v.d;
            else
                throw v.e;
        }
        _Et exception() {
            if (has_data)
                return NULL;
            else
                return v.e;
        }
        template<typename _Rt,typename... _At>
        _Rt ifExecute(_Rt f(_Dt,_At...), _At... args) {
            if (has_data)
                return f(v.d,args...);
            return NULL;
        }
        template<typename T>
        static auto null() {
            return fail<T>((exception_ptr)newException<logic_error>("值不存在!"));
        }
    };

    using _Optional = __Optional<nullptr_t, exception_ptr>;

    //IMAGE_OPTIONAL_HEADER64
    class __OptionalHeader {
        union {
            IMAGE_OPTIONAL_HEADER32 v32;
            IMAGE_OPTIONAL_HEADER64 v64;
        }v;
        enum Type{
            _32,
            _64
        }t;
        template<typename T>
        using strict = const T;
        template<typename T>
        strict<T> Strict(T in) {
            return (strict<T>)in;
        }
    public:
        template<typename _Dt,typename _Et = std::exception_ptr>
        using Optional = __Optional<_Dt, _Et>;
        __OptionalHeader(IMAGE_OPTIONAL_HEADER32 i) :t(_32) {
            v.v32 = i;
        }
        __OptionalHeader(IMAGE_OPTIONAL_HEADER64 i) :t(_64) {
            v.v64 = i;
        }
        Type type() {
            return t;
        }
        Optional<IMAGE_OPTIONAL_HEADER32> get32() {
            return t == _32 ? _Optional::success<IMAGE_OPTIONAL_HEADER32>(v.v32) : _Optional::null<IMAGE_OPTIONAL_HEADER32>();
        }
        Optional<IMAGE_OPTIONAL_HEADER64> get64() {
            return t == _64 ? _Optional::success<IMAGE_OPTIONAL_HEADER64>(v.v64) : _Optional::null<IMAGE_OPTIONAL_HEADER64>();
        }
    };

    class __PEHelper {
        __PEHelper(){}
    public:
#define _STREAM_TEMPLATE(name) template<class _##name##t>
#define _D_STREAM_TEMPLATE _STREAM_TEMPLATE(S)
#define __DST__ _D_STREAM_TEMPLATE
        __DST__ static void printInfo(IMAGE_DOS_HEADER h, _St& s) {
            s << "合法性:" << (h.e_magic == 0X5A4D ? "是" : "否") << endl;
            s << "堆栈入口:" << h.e_ss << ":" << h.e_sp << endl;
            s << "代码入口:" << h.e_cs << ":" << h.e_ip << endl;
            s << "PE头地址:" << h.e_lfanew << endl;
        }
        __DST__ static void printInfo(IMAGE_FILE_HEADER &h, _St& s) {
            s << "程序位数:" << (h.SizeOfOptionalHeader == 0XE0 ? "32位" : "64位") << endl;
            s << "运行平台:" << machine(h.Machine) << endl;
            s << "程序分段数:" << h.NumberOfSections << endl;
            s << "程序创建时间:" << ctime((const time_t*)&h.TimeDateStamp) << endl;
            s << "程序属性:" << characteristics(h.Characteristics) << endl;
        }
        __DST__ static void printInfo(IMAGE_OPTIONAL_HEADER32& h, _St s) {
            s << "合法性:" << (h.Magic == 0X10B ? "是" : "否") << endl;
            s << "连接器版本:" << (int)h.MajorLinkerVersion << "." << (int)h.MinorLinkerVersion << endl;
            s << "代码大小:" << h.SizeOfCode << endl;
            s << "初始化数据大小:" << h.SizeOfInitializedData << endl;
            s << "未初始化数据大小:" << h.SizeOfUninitializedData << endl;
            s << "程序入口点:" << h.AddressOfEntryPoint << endl;
            s << "代码基地址:" << h.BaseOfCode << endl;
            s << "数据基地址:" << h.BaseOfData << endl;
            s << "程序基地址:" << h.ImageBase << endl;
            s << "段对齐值:" << h.SectionAlignment << endl;
            s << "文件对齐值:" << h.FileAlignment << endl;
            s << "要求的操作系统版本:" << h.MajorOperatingSystemVersion << "." << h.MinorOperatingSystemVersion << endl;
            s << "程序版本:" << h.MajorImageVersion << "." << h.MinorImageVersion << endl;
            s << "子系统版本:" << h.MajorSubsystemVersion << "." << h.MinorSubsystemVersion << endl;
            s << "Win32版本:" << h.Win32VersionValue << endl;
            s << "程序大小:" << h.SizeOfImage << endl;
            s << "头部大小:" << h.SizeOfHeaders << endl;
            s << "校验和:" << h.CheckSum << endl;
            s << "子系统:" << subsystem(h.Subsystem) << endl;
            s << "DLL属性:" << dllcharacteristics(h.DllCharacteristics) << endl;
            s << "数据字典:" << endl;
            for (int i = 0; i < 16; i++) {
                s << "--字典第" << i << "项:" << endl;
                s << "----虚拟地址:" << h.DataDirectory[i].VirtualAddress << endl;
                s << "----大小:" << h.DataDirectory[i].Size << endl;
            }
        }
        __DST__ static void printInfo(IMAGE_OPTIONAL_HEADER64& h, _St s) {
            s << "合法性:" << (h.Magic == 0X20B ? "是" : "否") << endl;
            s << "连接器版本:" << (int)h.MajorLinkerVersion << "." << (int)h.MinorLinkerVersion << endl;
            s << "代码大小:" << h.SizeOfCode << endl;
            s << "初始化数据大小:" << h.SizeOfInitializedData << endl;
            s << "未初始化数据大小:" << h.SizeOfUninitializedData << endl;
            s << "程序入口点:" << h.AddressOfEntryPoint << endl;
            s << "代码基地址:" << h.BaseOfCode << endl;
            s << "程序基地址:" << h.ImageBase << endl;
            s << "段对齐值:" << h.SectionAlignment << endl;
            s << "文件对齐值:" << h.FileAlignment << endl;
            s << "要求的操作系统版本:" << h.MajorOperatingSystemVersion << "." << h.MinorOperatingSystemVersion << endl;
            s << "程序版本:" << h.MajorImageVersion << "." << h.MinorImageVersion << endl;
            s << "子系统版本:" << h.MajorSubsystemVersion << "." << h.MinorSubsystemVersion << endl;
            s << "Win32版本:" << h.Win32VersionValue << endl;
            s << "程序大小:" << h.SizeOfImage << endl;
            s << "头部大小:" << h.SizeOfHeaders << endl;
            s << "校验和:" << h.CheckSum << endl;
            s << "子系统:" << subsystem(h.Subsystem) << endl;
            s << "DLL属性:" << dllcharacteristics(h.DllCharacteristics) << endl;
            s << "数据字典:" << endl;
            for (int i = 0; i < 16; i++) {
                s << "--字典第" << i << "项:" << endl;
                s << "----虚拟地址:" << h.DataDirectory[i].VirtualAddress << endl;
                s << "----大小:" << h.DataDirectory[i].Size << endl;
            }
        }
        __DST__ static void printInfo(__OptionalHeader& h, _St &s) {
            h.get32().ifExecute(printInfo,s);
            h.get64().ifExecute(printInfo, s);
        }
        static bool is32BitProgram(IMAGE_FILE_HEADER& h) {
            return h.SizeOfOptionalHeader == 0XE0;
        }
        static auto ntHeaderOffset(IMAGE_DOS_HEADER &h) {
            return h.e_lfanew;
        }
        static bool hasNtHeader(IMAGE_DOS_HEADER &h) {
            return ntHeaderOffset(h) != 0;
        }
        static bool checkPeMagic(DWORD m) {
            return m == 0X00004550;
        }
        template<typename _Dt, class _St>
        static _Dt Read(_St& s) {
            _Dt d;
            Read(s, &d);
            return d;
        }
#define READ(t,s) Read<t, std::ifstream>(s)
#define NEW(t,n,s) t n = __PEHelper::READ(t,  s)
        __DST__ static __OptionalHeader readOptionalHeader(IMAGE_FILE_HEADER &h, _St& s) {
            if (is32BitProgram(h))
                return __OptionalHeader(Read<IMAGE_OPTIONAL_HEADER32, _St>(s));
            else
                return __OptionalHeader(Read<IMAGE_OPTIONAL_HEADER64, _St>(s));
        }
    };

    void Parse(ifstream& file,string name) {
        NEW(IMAGE_DOS_HEADER, dHead, file);
        ofstream dosinfo(name + ".dosinfo");
        dosinfo << "程序" << name << "的DOS信息——" << endl;
        __PEHelper::printInfo(dHead, dosinfo);
        dosinfo.close();

        //TODO:剥离DOS程序的代码段、数据段和堆栈段

        if (!__PEHelper::hasNtHeader(dHead))
            exit(0);

        file.seekg(__PEHelper::ntHeaderOffset(dHead));

        NEW(DWORD, peMagic, file);
        NEW(IMAGE_FILE_HEADER, fHead, file);
        ofstream peinfo(name + ".peinfo");
        peinfo << "程序" << name << "的PE信息——" << endl;
        peinfo << "合法性:" << (__PEHelper::checkPeMagic(peMagic) ? "是" : "否") << endl;
        __PEHelper::printInfo(fHead, peinfo);
        peinfo.close();

        __OptionalHeader oHead = __PEHelper::readOptionalHeader(fHead, file);
        ofstream ohinfo(name + ".ohinfo");
        ohinfo << "程序" << name << "的PE" << (__PEHelper::is32BitProgram(fHead) ? 32 : 64) << "位可选头信息——" << endl;
        __PEHelper::printInfo(oHead, ohinfo);
        ohinfo.close();
        /**
        IMAGE_OPTIONAL_HEADER32 oh32Head;
        IMAGE_OPTIONAL_HEADER64 oh64Head;
        IMAGE_DATA_DIRECTORY *dd;
        if (fHead.SizeOfOptionalHeader == 0XE0) {
            ofstream ohinfo(name + ".oh32info");
            Read(file, &oh32Head);
            ohinfo << "程序" << name << "的PE32位可选头信息——" << endl;
            ohinfo << "合法性:" << (oh32Head.Magic == 0X10B ? "是" : "否") << endl;
            ohinfo << "连接器版本:" << (int)oh32Head.MajorLinkerVersion << "." << (int)oh32Head.MinorLinkerVersion << endl;
            ohinfo << "代码大小:" << oh32Head.SizeOfCode << endl;
            ohinfo << "初始化数据大小:" << oh32Head.SizeOfInitializedData << endl;
            ohinfo << "未初始化数据大小:" << oh32Head.SizeOfUninitializedData << endl;
            ohinfo << "程序入口点:" << oh32Head.AddressOfEntryPoint << endl;
            ohinfo << "代码基地址:" << oh32Head.BaseOfCode << endl;
            ohinfo << "数据基地址:" << oh32Head.BaseOfData << endl;
            ohinfo << "程序基地址:" << oh32Head.ImageBase << endl;
            ohinfo << "段对齐值:" << oh32Head.SectionAlignment << endl;
            ohinfo << "文件对齐值:" << oh32Head.FileAlignment << endl;
            ohinfo << "要求的操作系统版本:" << oh32Head.MajorOperatingSystemVersion << "." << oh32Head.MinorOperatingSystemVersion << endl;
            ohinfo << "程序版本:" << oh32Head.MajorImageVersion << "." << oh32Head.MinorImageVersion << endl;
            ohinfo << "子系统版本:" << oh32Head.MajorSubsystemVersion << "." << oh32Head.MinorSubsystemVersion << endl;
            ohinfo << "Win32版本:" << oh32Head.Win32VersionValue << endl;
            ohinfo << "程序大小:" << oh32Head.SizeOfImage << endl;
            ohinfo << "头部大小:" << oh32Head.SizeOfHeaders << endl;
            ohinfo << "校验和:" << oh32Head.CheckSum << endl;
            ohinfo << "子系统:" << subsystem(oh32Head.Subsystem) << endl;
            ohinfo << "DLL属性:" << dllcharacteristics(oh32Head.DllCharacteristics) << endl;
            ohinfo << "数据字典:" << endl;
            for (int i = 0; i < 16; i++) {
                ohinfo << "--字典第" << i << "项:" << endl;
                ohinfo << "----虚拟地址:" << oh32Head.DataDirectory[i].VirtualAddress << endl;
                ohinfo << "----大小:" << oh32Head.DataDirectory[i].Size << endl;
            }
            dd = oh32Head.DataDirectory;
            ohinfo.close();
        }
        else {
            ofstream ohinfo(name + ".oh64info");
            Read(file, &oh64Head);
            ohinfo << "程序" << name << "的PE64位可选头信息——" << endl;
            ohinfo << "合法性:" << (oh64Head.Magic == 0X20B ? "是" : "否") << endl;
            ohinfo << "连接器版本:" << (int)oh64Head.MajorLinkerVersion << "." << (int)oh64Head.MinorLinkerVersion << endl;
            ohinfo << "代码大小:" << oh64Head.SizeOfCode << endl;
            ohinfo << "初始化数据大小:" << oh64Head.SizeOfInitializedData << endl;
            ohinfo << "未初始化数据大小:" << oh64Head.SizeOfUninitializedData << endl;
            ohinfo << "程序入口点:" << oh64Head.AddressOfEntryPoint << endl;
            ohinfo << "代码基地址:" << oh64Head.BaseOfCode << endl;
            ohinfo << "程序基地址:" << oh64Head.ImageBase << endl;
            ohinfo << "段对齐值:" << oh64Head.SectionAlignment << endl;
            ohinfo << "文件对齐值:" << oh64Head.FileAlignment << endl;
            ohinfo << "要求的操作系统版本:" << oh64Head.MajorOperatingSystemVersion << "." << oh64Head.MinorOperatingSystemVersion << endl;
            ohinfo << "程序版本:" << oh64Head.MajorImageVersion << "." << oh64Head.MinorImageVersion << endl;
            ohinfo << "子系统版本:" << oh64Head.MajorSubsystemVersion << "." << oh64Head.MinorSubsystemVersion << endl;
            ohinfo << "Win32版本:" << oh64Head.Win32VersionValue << endl;
            ohinfo << "程序大小:" << oh64Head.SizeOfImage << endl;
            ohinfo << "头部大小:" << oh64Head.SizeOfHeaders << endl;
            ohinfo << "校验和:" << oh64Head.CheckSum << endl;
            ohinfo << "子系统:" << subsystem(oh64Head.Subsystem) << endl;
            ohinfo << "DLL属性:" << dllcharacteristics(oh64Head.DllCharacteristics) << endl;
            ohinfo << "数据字典:" << endl;
            for (int i = 0; i < 16; i++) {
                ohinfo << "--字典第" << i << "项:" << endl;
                ohinfo << "----虚拟地址:" << oh64Head.DataDirectory[i].VirtualAddress << endl;
                ohinfo << "----大小:" << oh64Head.DataDirectory[i].Size << endl;
            }
            dd = oh64Head.DataDirectory;
            ohinfo.close();
        }

        auto RVA_of_IID = dd[1].VirtualAddress;
        long long min_RAW_offset = (long long)1e9, RAW_offset = 0;
        for (int i = 0; i < fHead.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER harder;
            Read(file, &harder);
            char sname[9];
            for (int j = 0; j < 8; j++)
                sname[j] = harder.Name[j];
            sname[8] = 0;
            ofstream sinfo(name + sname + ".sectioninfo");
            sinfo << "程序" << name << "的段信息——" << endl;
            sinfo << "段名称:" << sname << endl;
            sinfo << "虚拟地址:" << harder.VirtualAddress << endl;
            sinfo << "数据大小:" << harder.SizeOfRawData << endl;
            sinfo << "数据位置:" << harder.PointerToRawData << endl;
            sinfo << "属性:" << characteristics_s(harder.Characteristics) << endl;
            sinfo.close();
            
            auto temp = RVA_of_IID - harder.VirtualAddress;
            if (temp > 0 && RVA_of_IID - temp < min_RAW_offset)
                min_RAW_offset = temp, RAW_offset = harder.PointerToRawData;

            ofstream sdata(name + sname + ".sectiondata", ios::binary);
            auto pos1 = file.tellg();
            file.seekg(harder.PointerToRawData, ios::beg);
            try {
                char* data = new char[harder.SizeOfRawData];
                file.read(data, harder.SizeOfRawData);
                sdata.write(data, harder.SizeOfRawData);
                delete[] data;
            }
            catch (bad_alloc& ba) {
                cout << "无法分配内存!" << endl;
                const char* errormsg = "无法分配内存!";
                sdata.write(errormsg, strlen(errormsg));
            }
            file.seekg(pos1, ios::beg);
            sdata.close();
        }

        file.seekg(RAW_offset + min_RAW_offset, ios::beg);
        for (long long bytesrest = dd[1].Size; bytesrest > 0; bytesrest -= sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            IMAGE_IMPORT_DESCRIPTOR IID;
            Read(file, &IID);

        }
        /**/
    }
}

void ParsePEFile(string filename) {
    string realname = filename.substr(0, filename.find_last_of('.'));
    cout << "开始解析程序:" << realname << endl;
    ifstream file(filename, ios::binary);
    Details::Parse(file,realname);
}

int main()
{
    ParsePEFile("PEParser.exe");
    return 0;
}