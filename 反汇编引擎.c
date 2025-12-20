// 反汇编引擎.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "disasm.h"
#include "PETools.h"
 
#pragma pack(1)

#define FILEPATH "C:\\Users\\lijiaquan\\Desktop\\notepad.exe"  //此处修改为你要反汇编的可执行文件路径

/*unsigned char test_hex_codes[] = {

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
    

};*/



int main() {
	PVOID pFileBuffer = NULL;
	PVOID pImageBuffer = NULL;
    PVOID CodeBase = NULL;

    printf("========== x86 反汇编引擎测试 ==========\n\n");
    int offset = 0;
    ReadPEFile(FILEPATH, &pFileBuffer);
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)pDosHeader);
    PIMAGE_FILE_HEADER pFileHeader = &pNTHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
    DWORD SectionNum = pFileHeader->NumberOfSections;

    DWORD i;
    for (i = 0; i < SectionNum; i++)
    {
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE)
        {
            CodeBase = (PVOID)(pSectionHeader[i].VirtualAddress + (DWORD)pImageBuffer);
			break;
        }
    }


    DWORD test_size = pSectionHeader[i].Misc.VirtualSize;

    //int test_size = sizeof(test_hex_codes);
    
    while ((DWORD)offset < test_size) {
        DecodeContext ctx;
        DWORD currentVA = pOptionalHeader->ImageBase + pSectionHeader[i].VirtualAddress + offset;
        //int len = Disassemble(test_hex_codes + offset, offset, &ctx);
		int len = Disassemble((unsigned char*)CodeBase+offset, currentVA, &ctx);
        if (len <= 0) {
            printf("%08X: 无法解析\n", currentVA);
            break;
        }
        
        // 打印地址
        printf("%08X: ",  currentVA);
		// 打印机器码 (对齐到45个字符)，指令长度不超过15字节
        printf("%-45s ", ctx.hex_str);
        
        // 打印汇编
        printf("%s\n", ctx.asm_str);
        
        offset += len;
    }
    
    printf("\n========== 测试完成 ==========\n");
    printf("总共解析了 %d 字节\n", offset);
    
    return 0;
}

