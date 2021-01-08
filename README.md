# PeParser
## 简述:PeParser是一个基于C++,可以分析PE格式文件的开源库
### 计划功能:
  + 1:读取DOS文件格式(已实现)
  + 2:反编译DOS代码到汇编(准备实现)
  + 3:反编译DOS代码到C(未实现)
  + 4:读取PE文件格式(已实现)
  + 5:反编译PE代码到汇编(未实现)
  + 6:反编译PE代码到C(未实现)
  + 7:构建PE程序输入输出表(正在实现)

### 接口:
  PeParser的全部功能都在Details命名空间中 </br>
  [待实现]将会加入PeParser命名空间
  #### Details命名空间
    __PEHelper:该类是PeParser主要的对外接口 </br>
    该类无字段/成员函数 </br>
    静态函数: </br>
      __DST__ static void printInfo(IMAGE_DOS_HEADER h, _St& s):打印h的信息到输出流s </br>
      __DST__ static void printInfo(IMAGE_FILE_HEADER h, _St& s):打印h的信息到输出流s </br>
      __DST__ static void printInfo(IMAGE_OPTIONAL_HEADER32 h, _St& s):打印h的信息到输出流s </br>
      __DST__ static void printInfo(IMAGE_OPTIONAL_HEADER64 h, _St& s):打印h的信息到输出流s </br>
      __DST__ static void printInfo(__OptionalHeader h, _St& s):打印h的信息到输出流s </br>
      static bool is32BitProgram(IMAGE_FILE_HEADER& h):如果h是一个32位PE文件的一部分,则该函数返回true,反之返回false </br>
      static auto ntHeaderOffset(IMAGE_DOS_HEADER &h):根据给定的DOS头部h,返回PE头的位置 </br>
