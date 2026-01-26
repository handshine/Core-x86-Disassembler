// 反汇编引擎.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <stdio.h>
#include <windows.h>
#include "disasm.h"
#include "PETools.h"

#pragma pack(1)

// ================= 配置区：在这里一键切换 =================
#define MODE_ARRAY   0  // 使用内置测试数组
#define MODE_PE_FILE 1  // 解析外部 PE 文件

#define RUN_MODE     MODE_ARRAY   // <--- 修改这里切换模式

#define TARGET_PATH  "C:\\Windows\\SysWOW64\\notepad.exe" //此处修改为你要反汇编的可执行文件路径
// =========================================================
unsigned char test_hex_codes[] = {

    // 寄存器操作
    0x40,                 // INC EAX
    0x48,                 // DEC EAX
    0x50,                 // PUSH EAX
    0x58,                 // POP EAX
    0x89, 0xC3,           // MOV EBX, EAX
    0x01, 0xC8,           // ADD EAX, ECX

    // 立即数操作
    0xB8, 0x12, 0x34, 0x56, 0x78,  // MOV EAX, 0x78563412
    0x83, 0xC0, 0x01,     // ADD EAX, 1
    0x81, 0xC3, 0xEF, 0xBE, 0xAD, 0xDE,  // ADD EBX, 0xDEADBEEF
    0xB8, 0x10, 0x00, 0x00, 0x00,     //MOV EAX, 0x10
    0x83, 0xC0, 0x20,     //ADD EAX, 0x20  -> EAX=0x30, ZF=0
    0x83, 0xE8, 0x30,     //SUB EAX, 0x30  -> EAX=0x00, ZF=1

    // 内存操作（各种寻址模式）
   0x66, 0x8B, 0x45, 0x08,     // MOV AX, [EBP+8]
    0x89, 0x5D, 0xFC,     // MOV [EBP-4], EBX
    0x8B, 0x04, 0x24,     // MOV EAX, [ESP]
    0x8B, 0x1C, 0x08,     // MOV EBX, [EAX+ECX]
   0x67, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00,  // MOV DWORD PTR [BP-4], 0
   //0x66前缀测试
   0x60,
   0x61,
   0x66,0x60,
   0x66,0x61,
   0x66,0xa5,

   // 段前缀测试
   0x64, 0x8B, 0x05, 0x30, 0x00, 0x00, 0x00, // MOV EAX, FS:[0x30]
   0x26, 0x89, 0x03,                         // MOV ES:[EBX], EAX

   // 跳转指令
   0x74, 0x05,           // JZ +5
   0x75, 0x03,           // JNZ +3
   0xE9, 0x00, 0x00, 0x00, 0x00,  // JMP 0
   0xEB, 0xFE,           // JMP -2 (短跳转)

   // 函数调用和返回
   0xE8, 0x00, 0x00, 0x00, 0x00,  // CALL 0
   0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  // CALL DWORD PTR [0]
   0xC3,                 // RETN
   0xC2, 0x04, 0x00,     // RETN 4

   // 栈操作
   0x68, 0x78, 0x56, 0x34, 0x12,  // PUSH 0x12345678
   0x8D, 0x45, 0xFC,     // LEA EAX, [EBP-4]

   // 算术运算
   0x29, 0xC8,           // SUB EAX, ECX
   0xF7, 0xE3,           // MUL EBX
   0xF7, 0xFB,           // IDIV EBX

   // 逻辑运算
   0x21, 0xD8,           // AND EAX, EBX
   0x09, 0xC8,           // OR EAX, ECX
   0x31, 0xF6,           // XOR ESI, ESI
   0xD3, 0xE0,           // SHL EAX, CL

   // 比较和测试
   0x39, 0xD8,           // CMP EAX, EBX
   0x85, 0xC0,           // TEST EAX, EAX

   // 字符串操作
   0xA4,                 // MOVSB
   0xA6,                 // CMPSB
   0xAA,                 // STOSB
   0xAC,                 // LODSB

   // 标志位操作
   0x9C,                 // PUSHFD
   0x9D,                 // POPFD
   0xF8,                 // CLC
   0xFD,                 // STD


   // 前缀指令
   0x66, 0xB8, 0x34, 0x12,  // MOV AX, 0x1234 (操作数大小前缀)
   0xF3, 0x90,           // PAUSE (REP NOP)
   0xF3, 0xA4,           // REP MOVSB


   // 浮点指令
   0xD9, 0x45, 0x00,     // FLD DWORD PTR [EBP]
   0xDE, 0xC9,           // FMULP ST(1), ST

   // 特殊指令
   0xCD, 0x80,           // INT 0x80
   0xCC,                 // INT 3
   0x90,                 // NOP
   0xF4,                 // HLT

   // ========== 0xD8 (Single Real / Register) ==========
    0xD8, 0x00,                   // FADD DWORD PTR [EAX]
    0xD8, 0x18,                   // FCOMP DWORD PTR [EAX]
    0xD8, 0xC1,                   // FADD ST(0), ST(1)
    0xD8, 0xD2,                   // FCOM ST(2)
    0xD8, 0x44, 0x8D, 0x10,       // FADD DWORD PTR [EBP + ECX*4 + 0x10]

    // ========== 0xD9 (Single Real / Special) ==========
    0xD9, 0x00,                   // FLD DWORD PTR [EAX]
    0xD9, 0x18,                   // FSTP DWORD PTR [EAX]
    0xD9, 0x38,                   // FNSTCW WORD PTR [EAX]
    0xD9, 0xC0,                   // FLD ST(0)
    0xD9, 0xC9,                   // FXCH ST(1)
    0xD9, 0xD0,                   // FNOP
    0xD9, 0xE0,                   // FCHS (改变符号)
    0xD9, 0xE1,                   // FABS (绝对值)
    0xD9, 0xE8,                   // FLD1 (加载1.0)
    0xD9, 0xEB,                   // FLDPI (加载PI)
    0xD9, 0xFA,                   // FSQRT (平方根)
    0xD9, 0xFE,                   // FSIN (正弦)

    // ========== 0xDA (Int32 / CMOV) ==========
    0xDA, 0x00,                   // FIADD DWORD PTR [EAX]
    0xDA, 0x28,                   // FISUB DWORD PTR [EAX]
    0xDA, 0xC1,                   // FCMOVB ST(0), ST(1)
    0xDA, 0xE9,                   // FUCOMPP

    // ========== 0xDB (Int32 / Extended Real / CMOV) ==========
    0xDB, 0x00,                   // FILD DWORD PTR [EAX]
    0xDB, 0x28,                   // FLD TBYTE PTR [EAX] (80-bit)
    0xDB, 0x38,                   // FSTP TBYTE PTR [EAX]
    0xDB, 0xE2,                   // FCLEX
    0xDB, 0xF0,                   // FCOMI ST(0), ST(0)

};

// 用于统一管理解析目标的结构体
typedef struct {
    unsigned char* pBuffer;   // 数据缓冲区指针
    DWORD size;               // 数据大小
    DWORD baseVA;             // 起始虚拟地址 (用于打印)
    const char* sourceName;   // 来源名称
} DisasmTarget;

// 初始化目标函数：根据宏定义加载数据
BOOL InitDisasmTarget(DisasmTarget* target, PVOID* pOutImageBuffer) {
    if (RUN_MODE == MODE_ARRAY) {
        target->pBuffer = test_hex_codes;
        target->size = sizeof(test_hex_codes);
        target->baseVA = 0x00400000; // 数组模式给定一个假想基址
        target->sourceName = "Internal Test Array";
        return TRUE;
    } else {
        PVOID pFileBuffer = NULL;
        if (!ReadPEFile(TARGET_PATH, &pFileBuffer)) {
            printf("[错误] 无法读取文件: %s\n", TARGET_PATH);
            return FALSE;
        }
        CopyFileBufferToImageBuffer(pFileBuffer, pOutImageBuffer);

        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)*pOutImageBuffer;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)pDos + pDos->e_lfanew);
        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

        // 查找代码段 (.text)
        for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            if (pSec[i].Characteristics & IMAGE_SCN_CNT_CODE) {
                target->pBuffer = (unsigned char*)((DWORD)*pOutImageBuffer + pSec[i].VirtualAddress);
                target->size = pSec[i].Misc.VirtualSize;
                target->baseVA = pNt->OptionalHeader.ImageBase + pSec[i].VirtualAddress;
                target->sourceName = TARGET_PATH;
                return TRUE;
            }
        }
    }
    return FALSE;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    DisasmTarget target = { 0 };
    PVOID pImageBuffer = NULL; // 只有 PE 模式会用到并需要释放

    printf("==========================================\n");
    printf("   X86 Disassembly Engine - Manager\n");
    printf("==========================================\n");

    if (!InitDisasmTarget(&target, &pImageBuffer)) {
        printf("初始化失败，请检查配置。\n");
        return -1;
    }

    printf("[模式] %s\n", (RUN_MODE == MODE_PE_FILE) ? "PE文件解析" : "静态数组测试");
    printf("[目标] %s\n", target.sourceName);
    printf("[基址] 0x%08X | [大小] %u 字节\n", target.baseVA, target.size);
    printf("------------------------------------------\n\n");

    DWORD offset = 0;
    int lineCount = 0;
    while (offset < target.size) {
        DecodeContext ctx;
        DWORD currentVA = target.baseVA + offset;

        // 调用反汇编函数
        int len = Disassemble(target.pBuffer + offset, currentVA, &ctx);

        if (len <= 0) {
            printf("%08X: <解析失败或未知指令>\n", currentVA);
            break;
        }

        // 统一的输出格式
        // 地址 | 机器码 (对齐) | 汇编指令
        printf("%08X:  %-30s  %s\n", currentVA, ctx.hex_str, ctx.asm_str);

        offset += len;
        lineCount++;

        // 每 10000 行暂停，按回车继续
        if (RUN_MODE == MODE_PE_FILE && lineCount % 10000 == 0) {
            printf("\n--- 已显示 %d 行，按回车继续 ---\n", lineCount);
            getchar();
        }
    }

    printf("\n------------------------------------------\n");
    printf("解析完成。总字节: %d\n", offset);

    return 0;
}

