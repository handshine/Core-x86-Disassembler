// disasm.h
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define MAX_INSTRUCTION_LENGTH 15
#define MAX_GROUPS 17
#define MAX_REG_COUNT 8
#define IS_PREFIX 1
#define HAS_MODRM 1

#ifdef __cplusplus //兼容C++
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>



// 操作数类型枚举 
typedef enum {
    NONE = 0,
	// 寄存器操作数
    Gb,   // 通用寄存器 (8 位)
	Gw,   // 通用寄存器 (16 位)
    Gv,   // 通用寄存器 (32/64 位)
	Gz,   // 在 64 位模式下，强制为 32 位操作数；在 16/32 位模式下，其行为与 Gv 相同。
    Eb,   // 内存或 8 位寄存器
	Ew,   // 内存或 16 位寄存器
    Ev,   // 内存或 16/32/64 位寄存器
	// 立即数操作数
    Ib,   // 8 位立即数
	Iw,   // 16 位立即数
	Iz,   // 16/32位立即数，大小取决于操作数大小前缀,最大4字节
	Iv,   // 16/32/64 位立即数，大小取决于操作数大小前缀
	Jb,   // 8 位相对偏移(用于跳转指令)
	Jz,   // 16/32 位相对偏移(用于跳转指令)，大小取决于操作数大小前缀

	Mv,   // 内存操作数 (16/32/64 位)
    Ma,   // Ma 专门用于 BOUND 指令。指向的是一个“成对”的内存操作数（边界值）。在 16 位模式下，它读入 32 位（两个 word）；在 32 位模式下，它读入 64 位（两个 dword）。
	M,    // 仅限内存。ModR/M 字节的 r/m 字段必须指向内存，如果是寄存器则指令无效。
	Mp,   // 内存或 16/32 位指针(段:偏移)，用于 LDS 和 LES 指令。
	Sw,   // 段寄存器 (16 位)
	Ap,   // / Ap: 直接远指针(无ModR/M)。32位读6字节(4off+2seg)，16位读4字节(2off+2seg)，注意偏移在前段在后。
	Ob,   // 8 位偏移(无ModR/M)
	Ov,   // 16/32/64 位偏移(无ModR/M)

	OP_AL,   // AL 寄存器
	OP_CL,   // CL 寄存器
	OP_DL,   // DL 寄存器
	OP_BL,   // BL 寄存器
	OP_AH,   // AH 寄存器
	OP_CH,   // CH 寄存器
	OP_DH,   // DH 寄存器
	OP_BH,   // BH 寄存器

	OP_DX,  // DX 寄存器，用于 IN/OUT 指令中的端口

	OP_rAX,  // AX/EAX/RAX 寄存器
	OP_rCX,  
	OP_rDX,
	OP_rBX,
	OP_rSP,
	OP_rBP,
	OP_rSI,
	OP_rDI,

	OP_ES,  // ES 段寄存器
	OP_CS,  
	OP_SS,  
	OP_DS,  
	OP_FS,
	OP_GS,

	OP_ONE, //  常数 1，用于某些指令的默认计数值

    // FPU 寄存器
    OP_ST0,
    OP_STi,

    // FPU Memory
    M_F32,  // 32 位浮点数（float / DWORD）
    M_F64,  // 64 位浮点数（double / QWORD）
    M_F80,  // 80 位扩展浮点数（long double / TBYTE）
    M_I16,  // 16 位整数（WORD）
    M_I32,  // 32 位整数（DWORD）
    M_I64,  // 64 位整数（QWORD）
    M_BCD,  // BCD 压缩十进制数（TBYTE，常用于 FBSTP/FBLD）
    M_ENV,  // x87 FPU 环境块（FNSTENV/FLDENV）
    M_SW,   // x87 状态字（Status Word，16 位）
    M_CW,   // x87 控制字（Control Word，16 位）
    M_STATE,// x87 FPU 完整状态区（FSAVE/FRSTOR）


    // ... 可以继续添加更多类型
} OperandType;

// 指令分组表项
typedef struct {
    // 操作码扩展值 (3 位)
    uint8_t opcode_extension;
    // 助记符
    const char* mnemonic;
    // 操作数类型
    OperandType operand[3];
} GroupEntry;

//指令表项
typedef struct {
    // 助记符 (如果是 Group 指令，这里可能为空，或者填一个特殊的标记)
    const char* mnemonic;

    //是否是前缀？( 1 = 是, 0 = 否 )
    bool is_prefix;

    // 后面是否接 ModR/M 字节？( 1 = 是, 0 = 否 )
    // 大部分运算指令都需要，只有像 NOP, PUSH r32 这种不需要
    bool has_modrm;

    // 操作数类型 (比如: OPERAND_TYPE_Gv, OPERAND_TYPE_Eb)
    // 这决定了我们如何解析 ModR/M 和 立即数
    OperandType op1,op2,op3;

    GroupEntry* group_table;

} OpcodeEntry;

//指令结构体，存解码
typedef struct {
    // 输入
    const uint8_t* buffer;
    int max_len;
    int pos;
    bool mode64;
    uint32_t eip; // 当前指令的 EIP (用于计算相对跳转的绝对地址)

    // 前缀状态
	bool pfx_lock;//0xF0
    bool pfx_repne;//0xF2
    bool pfx_rep;//0xF3
    uint8_t pfx_op_size; // 0x66
    uint8_t pfx_addr_size; // 0x67
    uint8_t pfx_segment; // 段覆盖前缀

    // 双字节操作码标记
    bool is_two_byte_opcode;

    // 指令组件
    uint8_t opcode;
    bool has_modrm;
    uint8_t modrm;
    uint8_t mod, reg, rm;

    bool has_sib;
    uint8_t sib;
    uint8_t scale, index, base;

    int32_t disp;
    int disp_len; // 0, 1, 4

    int64_t imm;
    int imm_len; // 0, 1, 2, 4, 8

    int64_t imm2; // 第二个立即数 (例如 ENTER 指令)
    int imm2_len;

    // 结果
    OpcodeEntry entry;
    char hex_str[32]; // 存储机器码的十六进制字符串
    char asm_str[128]; // 最终汇编
} DecodeContext;

// 反汇编一条指令
// buffer: 指令字节流
// eip: 当前指令的地址(用于计算相对跳转)
// out_ctx: 输出解码上下文
// 返回值: 指令长度(字节)
int Disassemble(uint8_t* buffer, uint32_t eip, DecodeContext* out_ctx);

// 获取寄存器名称
// reg_size: 寄存器大小 (1=段寄存器, 8, 16, 32)
// reg_index: 寄存器索引
const char* GetRegisterName(int reg_size, int reg_index);

// 指令各组件解析
void ParsePrefixes(DecodeContext* ctx);
void ParseModRM(DecodeContext* ctx);
void ParseSIB(DecodeContext* ctx);
void ParseDisplacement(DecodeContext* ctx);
void ParseImmediate(DecodeContext* ctx, OperandType type, int imm_index);
void ParseFPU(DecodeContext* ctx);
// 主解析函数--返回单次解析指令长度
int ParseInstuction(uint8_t* buffer, uint32_t eip, DecodeContext* out_ctx);

// 结果格式化
void FormatOperand(DecodeContext* ctx, char* buf, int size, OperandType type, int* imm_index);
void FormatModRM(DecodeContext* ctx, char* buf, int size, OperandType type);
//主格式化打印函数
void FormatInstruction(uint8_t* buffer, DecodeContext* out_ctx);


#ifdef __cplusplus
}
#endif
