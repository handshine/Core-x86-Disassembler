#include "disasm.h"

const GroupEntry group_tables[MAX_GROUPS + 1][MAX_REG_COUNT] = {
    // Group 1 (0x80 /0x81 /0x83)
    [0] = {
        {0, "ADD", NONE, NONE, NONE},
        {1, "OR",  NONE, NONE, NONE},
        {2, "ADC", NONE, NONE, NONE},
        {3, "SBB", NONE, NONE, NONE},
        {4, "AND", NONE, NONE, NONE},
        {5, "SUB", NONE, NONE, NONE},
        {6, "XOR", NONE, NONE, NONE},
        {7, "CMP", NONE, NONE, NONE},
    },
	// Group 1A (0x8F)
    [1] = {{0,"POP", Ev, NONE, NONE}},
	// Group 2 (0xC0 /0xC1/0xD0/0xD1/0xD2/0xD3)
    [2] = {
        {0,"ROL",NONE,NONE,NONE},
        {1,"ROR",NONE,NONE,NONE},
        {2,"RCL",NONE,NONE,NONE},
        {3,"RCR",NONE,NONE,NONE},
        {4,"SHL",NONE,NONE,NONE},
        {5,"SHR",NONE,NONE,NONE},
        {6,NULL,NONE,NONE,NONE},
        {7,"SAR",NONE,NONE,NONE},

     },
	 //Group 3 (0xF6)
    [3] = {
        {0, "TEST", Eb, Ib,   NONE}, 
        {1, NULL,   NONE, NONE, NONE}, 
        {2, "NOT",  Eb, NONE, NONE},
        {3, "NEG",  Eb, NONE, NONE}, 
        {4, "MUL",  OP_AL, Eb, NONE}, 
        {5, "IMUL", OP_AL, Eb, NONE}, 
        {6, "DIV",  OP_AL, Eb, NONE}, 
        {7, "IDIV", OP_AL, Eb, NONE}, 
    },
    // Group 3 (0xF7)
    [17] = {
        {0, "TEST", Ev, Iz,   NONE},
        {1, NULL,   NONE, NONE, NONE},
        {2, "NOT",  Ev, NONE, NONE},
        {3, "NEG",  Ev, NONE, NONE},
        {4, "MUL",  OP_rAX, Ev, NONE},
        {5, "IMUL", OP_rAX, Ev, NONE},
        {6, "DIV",  OP_rAX, Ev, NONE},
        {7, "IDIV", OP_rAX, Ev, NONE},
     },
     // Group 4 (0xFE)
     [4] = {
        {0, "INC", Eb, NONE, NONE},
        {1, "DEC", Eb, NONE, NONE},
	 },
     //Group 5 (0xFF)
     [5] = {
        {0, "INC", Ev, NONE, NONE},
        {1, "DEC", Ev, NONE, NONE},
        {2, "CALL", Ev, NONE, NONE},
        {3, "CALL FAR", Ap, NONE, NONE},
        {4, "JMP",  Ev, NONE, NONE},
        {5, "JMP FAR",  Ap, NONE, NONE},
        {6, "PUSH", Ev, NONE, NONE},

	 },
	 // Group 11 (0xC6 /0xC7)
     [11] = {  {0, "MOV", NONE, NONE, NONE} },



	// ... 可以继续添加更多 Group 表


};

const OpcodeEntry opcode_table[256] = {
    // 0x00 - 0x0F
    [0x00] = {"ADD",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x01] = {"ADD",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x02] = {"ADD",0, HAS_MODRM, Gb, Eb, NONE, NULL},
    [0x03] = {"ADD",0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x04] = {"ADD",0, 0, OP_AL, Ib, NONE, NULL},
    [0x05] = {"ADD",0, 0, OP_rAX, Iz, NONE, NULL},
    [0x06] = {"PUSH", 0, 0, OP_ES, NONE, NONE, NULL},
    [0x07] = {"POP", 0, 0, OP_ES, NONE, NONE, NULL},
    [0x08] = {"OR",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x09] = {"OR",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x0a] = {"OR",0, HAS_MODRM, Gb, Eb, NONE, NULL},
    [0x0b] = {"OR",0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x0c] = {"OR",0, 0, OP_AL, Ib, NONE, NULL},
    [0x0d] = {"OR",0, 0, OP_rAX, Iz, NONE, NULL},
    [0x0e] = {"PUSH",0, 0, OP_CS, NONE, NONE, NULL},
	[0x0f] = { NULL ,IS_PREFIX,0, NONE , NONE, NONE, NULL}, //0F扩展前缀
	//0x10 - 0x1F
	[0x10] = {"ADC",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x11] = {"ADC",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x12] = {"ADC",0, HAS_MODRM, Gb, Eb, NONE, NULL},
    [0x13] = {"ADC",0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x14] = {"ADC",0, 0, OP_AL, Ib, NONE, NULL},
    [0x15] = {"ADC",0, 0, OP_rAX, Iz, NONE, NULL},
    [0x16] = {"PUSH", 0, 0, OP_SS, NONE, NONE, NULL},
    [0x17] = {"POP", 0, 0, OP_SS, NONE, NONE, NULL},
    [0x18] = {"SBB",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x19] = {"SBB",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x1a] = {"SBB",0, HAS_MODRM, Gb, Eb, NONE, NULL},
    [0x1b] = {"SBB",0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x1c] = {"SBB",0, 0, OP_AL, Ib, NONE, NULL},
    [0x1d] = {"SBB",0, 0, OP_rAX, Iz, NONE, NULL},
    [0x1e] = {"PUSH",0, 0, OP_DS , NONE , NONE , NULL},
    [0x1f] = {"POP",0 , 0 , OP_DS , NONE , NONE , NULL},
    //0x20 - 0x2F
    [0x20] = {"AND",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x21] = {"AND",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x22] = {"AND",0, HAS_MODRM, Gb, Eb, NONE, NULL},
    [0x23] = {"AND",0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x24] = {"AND",0, 0, OP_AL, Ib, NONE, NULL},
    [0x25] = {"AND",0, 0, OP_rAX, Iz, NONE, NULL},
	[0x26] = { NULL ,IS_PREFIX,0, NONE , NONE, NONE, NULL}, //ES段前缀
    [0x27] = {"DAA",0, 0, NONE, NONE, NONE, NULL},
    [0x28] = {"SUB",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x29] = {"SUB",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x2a] = {"SUB",0, HAS_MODRM, Gb, Eb, NONE, NULL},
    [0x2b] = {"SUB",0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x2c] = {"SUB",0, 0, OP_AL, Ib, NONE, NULL},
    [0x2d] = {"SUB",0, 0, OP_rAX, Iz, NONE, NULL},
	[0x2e] = { NULL ,IS_PREFIX,0, NONE , NONE, NONE, NULL}, //CS段前缀
	[0x2f] = {"DAS",0 , 0 , NONE , NONE , NONE , NULL},
    //0x30 - 0x3F
    [0x30] = {"XOR",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x31] = {"XOR",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x32] = {"XOR",0, HAS_MODRM, Gb, Eb, NONE, NULL},
    [0x33] = {"XOR",0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x34] = {"XOR",0, 0, OP_AL, Ib, NONE, NULL},
    [0x35] = {"XOR",0, 0, OP_rAX, Iz, NONE, NULL},
	[0x36] = { NULL ,IS_PREFIX,0, NONE , NONE, NONE, NULL}, //SS段前缀
    [0x37] = {"AAA",0 , 0 , NONE , NONE , NONE , NULL},
    [0x38] = {"CMP",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x39] = {"CMP",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x3a] = {"CMP",0, HAS_MODRM, Gb, Eb, NONE, NULL},
    [0x3b] = {"CMP",0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x3c] = {"CMP",0, 0, OP_AL, Ib, NONE, NULL},
    [0x3d] = {"CMP",0, 0, OP_rAX, Iz, NONE, NULL},
	[0x3e] = { NULL ,IS_PREFIX,0, NONE , NONE, NONE, NULL}, //DS段前缀
	[0x3f] = {"AAS",0 , 0 , NONE , NONE , NONE , NULL},
    //0x40 - 0x4F
    [0x40] = {"INC",0, 0, OP_rAX, NONE, NONE, NULL},
    [0x41] = {"INC",0, 0, OP_rCX, NONE, NONE, NULL},
    [0x42] = {"INC",0, 0, OP_rDX, NONE, NONE, NULL},
    [0x43] = {"INC",0, 0, OP_rBX, NONE, NONE, NULL},
    [0x44] = {"INC",0, 0, OP_rSP, NONE, NONE, NULL},
    [0x45] = {"INC",0, 0, OP_rBP, NONE, NONE, NULL},
    [0x46] = {"INC",0, 0, OP_rSI, NONE, NONE, NULL},
    [0x47] = {"INC",0, 0, OP_rDI, NONE, NONE, NULL},
    [0x48] = {"DEC",0, 0, OP_rAX, NONE, NONE, NULL},
    [0x49] = {"DEC",0, 0, OP_rCX, NONE, NONE, NULL},
    [0x4a] = {"DEC",0, 0, OP_rDX, NONE, NONE, NULL},
    [0x4b] = {"DEC",0, 0, OP_rBX, NONE, NONE, NULL},
    [0x4c] = {"DEC",0, 0, OP_rSP, NONE, NONE, NULL},
    [0x4d] = {"DEC",0, 0, OP_rBP, NONE, NONE, NULL},
    [0x4e] = {"DEC",0, 0, OP_rSI, NONE, NONE, NULL},
	[0x4f] = {"DEC",0, 0, OP_rDI, NONE, NONE, NULL},
    //0x50 - 0x5F
    [0x50] = {"PUSH",0, 0, OP_rAX, NONE, NONE, NULL},
    [0x51] = {"PUSH",0, 0, OP_rCX, NONE, NONE, NULL},
    [0x52] = {"PUSH",0, 0, OP_rDX, NONE, NONE, NULL},
    [0x53] = {"PUSH",0, 0, OP_rBX, NONE, NONE, NULL},
    [0x54] = {"PUSH",0, 0, OP_rSP, NONE, NONE, NULL},
    [0x55] = {"PUSH",0, 0, OP_rBP, NONE, NONE, NULL},
    [0x56] = {"PUSH",0, 0, OP_rSI, NONE, NONE, NULL},
    [0x57] = {"PUSH",0, 0, OP_rDI, NONE, NONE, NULL},
    [0x58] = {"POP",0, 0, OP_rAX, NONE, NONE, NULL},
    [0x59] = {"POP",0, 0, OP_rCX, NONE, NONE, NULL},
    [0x5a] = {"POP",0, 0, OP_rDX, NONE, NONE, NULL},
    [0x5b] = {"POP",0, 0, OP_rBX, NONE, NONE, NULL},
    [0x5c] = {"POP",0, 0, OP_rSP , NONE , NONE , NULL},
    [0x5d] = {"POP",0 , 0 , OP_rBP , NONE , NONE , NULL},
	[0x5e] = {"POP",0 , 0 , OP_rSI , NONE , NONE , NULL},
	[0x5f] = { "POP",0 , 0 , OP_rDI , NONE , NONE , NULL },
    //0x60 - 0x6F
    [0x60] = {"PUSHAD",0, 0, NONE, NONE, NONE, NULL}, //注意有66前缀时，修改当前分析项助记词PUSHA
    [0x61] = {"POPAD",0, 0, NONE, NONE, NONE, NULL}, //
    [0x62] = {"BOUND",0, HAS_MODRM, Gv, Mv, NONE, NULL},
    [0x63] = {"ARPL",0, HAS_MODRM, Ew, Gw, NONE, NULL},
	[0x64] = { NULL ,IS_PREFIX,0, NONE , NONE, NONE, NULL }, //FS段前缀
	[0x65] = { NULL ,IS_PREFIX,0, NONE , NONE, NONE, NULL }, //GS段前缀
	[0x66] = { NULL ,IS_PREFIX,0, NONE , NONE, NONE, NULL }, //操作数大小前缀
    [0x67] = { NULL ,IS_PREFIX,0, NONE , NONE, NONE, NULL}, //地址大小前缀
    [0x68] = {"PUSH",0, 0, Iz, NONE, NONE, NULL},
    [0x69] = {"IMUL",0, HAS_MODRM, Gv, Ev, Iz, NULL},
    [0x6a] = {"PUSH",0, 0, Ib, NONE, NONE, NULL},
    [0x6b] = {"IMUL",0, HAS_MODRM, Gv, Ev, Ib, NULL},
    [0x6c] = {"INSB",0, 0, NONE, NONE, NONE, NULL},
    [0x6d] = {"INSW",0, 0, NONE, NONE, NONE, NULL},
	[0x6e] = { "OUTSB",0, 0, NONE, NONE, NONE, NULL },
    [0x6f] = { "OUTSW",0, 0, NONE, NONE, NONE, NULL },
    //0x70 - 0x7F
    [0x70] = {"JO",0, 0, Jb, NONE, NONE, NULL},
    [0x71] = {"JNO",0, 0, Jb, NONE, NONE, NULL},
    [0x72] = {"JB",0, 0, Jb, NONE, NONE, NULL},
    [0x73] = {"JNB",0, 0, Jb, NONE, NONE, NULL},
    [0x74] = {"JZ",0, 0, Jb, NONE, NONE, NULL},
    [0x75] = {"JNZ",0, 0, Jb, NONE, NONE, NULL},
    [0x76] = {"JBE",0, 0, Jb, NONE, NONE, NULL},
    [0x77] = {"JA",0, 0, Jb, NONE, NONE, NULL},
    [0x78] = {"JS",0, 0, Jb, NONE, NONE, NULL},
    [0x79] = {"JNS",0, 0, Jb, NONE, NONE, NULL},
    [0x7a] = {"JP",0, 0, Jb, NONE, NONE, NULL},
    [0x7b] = {"JNP",0, 0, Jb, NONE, NONE, NULL},
    [0x7c] = {"JL",0, 0, Jb , NONE , NONE , NULL},
    [0x7d] = {"JNL",0 , 0 , Jb , NONE , NONE , NULL},
	[0x7e] = { "JLE",0 , 0 , Jb , NONE , NONE , NULL },
    [0x7f] = {"JG",0, 0, Jb, NONE, NONE, NULL},
	//0x80 - 0x8F
	[0x80] = { NULL, 0, HAS_MODRM, Eb, Ib, NONE, (GroupEntry*)group_tables[0] },  //Group 1 特例：group_tables[0]，group_tables[1]group_id都设置为1，方便判断。
    [0x81] = {NULL, 0, HAS_MODRM, Ev, Iz, NONE, (GroupEntry*)group_tables[0]},
	[0x82] = { NULL, 0, HAS_MODRM, Eb, Ib, NONE, (GroupEntry*)group_tables[0] },
    [0x83] = {NULL, 0, HAS_MODRM, Ev, Ib, NONE, (GroupEntry*)group_tables[0]},
    /*
    操作数到底该听谁的？
    答案是：采用“继承 + 覆盖”的策略。
    不用加新参数。你需要理解 Intel 文档的一个潜规则：
        对于 Group 1 (0x80 - 0x83) 这类指令：主表（Main Map）定操作数类型，Group 表定助记符。
        对于 Group 3 (0xF6 - 0xF7) 这类指令：Group 表既定助记符，也定操作数类型（会覆盖主表）。
    */
    [0x84] = {"TEST",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x85] = {"TEST",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x86] = {"XCHG",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x87] = {"XCHG",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x88] = {"MOV",0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0x89] = {"MOV",0, HAS_MODRM, Ev, Gv, NONE, NULL},
    [0x8a] = {"MOV",0, HAS_MODRM, Gb, Eb, NONE, NULL},
    [0x8b] = {"MOV",0, HAS_MODRM, Gv, Ev, NONE, NULL},
	[0x8c] = { "MOV",0, HAS_MODRM, Ew, Sw , NONE , NULL }, //Sw用reg字段表示段寄存器,打印时注意解析
    [0x8d] = {"LEA",0, HAS_MODRM, Gv, M , NONE , NULL},
    [0x8e] = {"MOV",0, HAS_MODRM, Sw , Ew , NONE , NULL},
	[0x8f] = { NULL , 0, HAS_MODRM , NONE , NONE , NONE , (GroupEntry*)group_tables[1] }, //Group 1A
    //0x90 - 0x9F
    [0x90] = {"NOP",0, 0, NONE, NONE, NONE, NULL},       //F3前缀时为暂停PAUSE
    [0x91] = {"XCHG",0, 0, OP_rAX, OP_rCX, NONE, NULL},
    [0x92] = {"XCHG",0, 0, OP_rAX, OP_rDX, NONE, NULL},
    [0x93] = {"XCHG",0, 0, OP_rAX, OP_rBX, NONE, NULL},
    [0x94] = {"XCHG",0, 0, OP_rAX, OP_rSP, NONE, NULL},
    [0x95] = {"XCHG",0, 0, OP_rAX, OP_rBP, NONE, NULL},
    [0x96] = {"XCHG",0, 0, OP_rAX, OP_rSI, NONE, NULL},
    [0x97] = {"XCHG",0, 0, OP_rAX, OP_rDI, NONE, NULL},
    [0x98] = {"CWDE",0, 0, NONE, NONE, NONE, NULL},  //66前缀时，修改当前分析项助记词为CBW
    [0x99] = {"CDQ",0, 0, NONE, NONE, NONE, NULL},   //66前缀时，修改当前分析项助记词为CWD
	[0x9a] = { "CALL",0, 0, Ap , NONE , NONE , NULL },  //调用远程过程
    [0x9b] = {"FWAIT",0, 0, NONE, NONE, NONE, NULL},
	[0x9c] = { "PUSHFD",0, 0, NONE , NONE , NONE , NULL }, //66前缀时，修改当前分析项助记符为PUSHF
	[0x9d] = {"POPFD",0 , 0 , NONE , NONE , NONE , NULL }, //66前缀时，修改当前分析项助记符为POPF
	[0x9e] = {"SAHF",0, 0, NONE , NONE , NONE , NULL },
    [0x9f] = {"LAHF",0, 0, NONE , NONE , NONE , NULL },
	//0xA0 - 0xAF
    [0xa0] = {"MOV",0, 0, OP_AL, Ob, NONE, NULL},
    [0xa1] = {"MOV",0, 0, OP_rAX, Ov, NONE, NULL},
    [0xa2] = {"MOV",0, 0, Ob, OP_AL, NONE, NULL},
    [0xa3] = {"MOV",0, 0, Ov, OP_rAX, NONE, NULL},
    [0xa4] = {"MOVSB",0, 0, NONE, NONE, NONE, NULL},
	[0xa5] = {"MOVSD",0, 0, NONE, NONE, NONE, NULL }, //66前缀时为MOVSW
    [0xa6] = {"CMPSB",0, 0, NONE, NONE, NONE, NULL},
	[0xa7] = {"CMPSD",0, 0, NONE, NONE, NONE, NULL }, //66前缀时为CMPSW
    [0xa8] = {"TEST",0, 0, OP_AL, Ib, NONE, NULL},
    [0xa9] = {"TEST",0, 0, OP_rAX, Iz, NONE, NULL},
    [0xaa] = {"STOSB",0, 0, NONE, NONE, NONE, NULL},
	[0xab] = {"STOSD",0, 0, NONE, NONE, NONE, NULL },  //66前缀时为STOSW
    [0xac] = {"LODSB",0, 0, NONE , NONE , NONE , NULL},
	[0xad] = { "LODSD",0 , 0 , NONE , NONE , NONE , NULL }, //66前缀时为LODSW
    [0xae] = {"SCASB",0 , 0 , NONE , NONE , NONE , NULL},
	[0xaf] = { "SCASD",0 , 0 , NONE , NONE , NONE , NULL }, //66前缀时为SCASW
    //0xB0 - 0xBF
    [0xb0] = {"MOV",0, 0, OP_AL, Ib, NONE, NULL},
    [0xb1] = {"MOV",0, 0, OP_CL, Ib, NONE, NULL},
    [0xb2] = {"MOV",0, 0, OP_DL, Ib, NONE, NULL},
    [0xb3] = {"MOV",0, 0, OP_BL, Ib, NONE, NULL},
    [0xb4] = {"MOV",0, 0, OP_AH, Ib, NONE, NULL},
    [0xb5] = {"MOV",0, 0, OP_CH, Ib, NONE, NULL},
    [0xb6] = {"MOV",0, 0, OP_DH, Ib, NONE, NULL},
    [0xb7] = {"MOV",0, 0, OP_BH, Ib, NONE, NULL},
    [0xb8] = {"MOV",0, 0, OP_rAX, Iv, NONE, NULL},
    [0xb9] = {"MOV",0, 0, OP_rCX, Iv, NONE, NULL},
    [0xba] = {"MOV",0, 0, OP_rDX, Iv, NONE, NULL},
    [0xbb] = {"MOV",0, 0, OP_rBX, Iv, NONE, NULL},
	[0xbc] = { "MOV",0, 0, OP_rSP, Iv, NONE, NULL },
    [0xbd] = {"MOV",0, 0, OP_rBP, Iv, NONE, NULL},
	[0xbe] = { "MOV",0, 0, OP_rSI, Iv, NONE, NULL },
	[0xbf] = { "MOV",0, 0, OP_rDI, Iv, NONE, NULL },
    //0xC0 - 0xCF
    [0xc0] = {NULL,0, HAS_MODRM, Eb, Ib, NONE, (GroupEntry*)group_tables[2]},
    [0xc1] = {NULL,0, HAS_MODRM, Ev, Ib, NONE, (GroupEntry*)group_tables[2] },
    [0xc2] = {"RETN",0, 0, Iw, NONE, NONE, NULL},
    [0xc3] = {"RETN",0, 0, NONE, NONE, NONE, NULL},
    [0xc4] = {"LES",0, HAS_MODRM, Gz, Mp, NONE, NULL},
    [0xc5] = {"LDS",0, HAS_MODRM, Gz, Mp, NONE, NULL},
    [0xc6] = {"MOV",0, HAS_MODRM, Eb, Ib, NONE, (GroupEntry*)group_tables[11]},
    [0xc7] = { "MOV",0, HAS_MODRM, Ev, Iz, NONE, (GroupEntry*)group_tables[11]},
    [0xc8] = { "ENTER",0, 0, Iw, Ib, NONE, (GroupEntry*)group_tables[11]},
	[0xc9] = { "LEAVE",0, 0, NONE, NONE, NONE, NULL },
    [0xca] = {"RETF",0, 0, Iw, NONE, NONE, NULL},
    [0xcb] = {"RETF",0, 0, NONE, NONE, NONE, NULL},
    [0xcc] = {"| INT 3",0, 0, NONE, NONE, NONE, NULL},
    [0xcd] = {"INT",0, 0, Ib, NONE, NONE, NULL},
    [0xce] = {"INTO",0, 0, NONE, NONE, NONE, NULL},
	[0xcf] = { "IRETD",0, 0, NONE, NONE, NONE, NULL }, //66前缀时为IRET
    //0xD0 - 0xDF
    [0xD0] = {NULL,0, HAS_MODRM, Eb, OP_ONE, NONE, (GroupEntry*)group_tables[2]},
    [0xD1] = {NULL,0, HAS_MODRM, Ev, OP_ONE, NONE, (GroupEntry*)group_tables[2]},
    [0xD2] = {NULL,0, HAS_MODRM, Eb, OP_CL, NONE, (GroupEntry*)group_tables[2]},
    [0xD3] = {NULL,0, HAS_MODRM, Ev, OP_CL, NONE, (GroupEntry*)group_tables[2]},
    [0xD4] = {"AAM",0, 0, Ib, NONE, NONE, NULL},
    [0xD5] = {"AAD",0, 0, Ib, NONE, NONE, NULL},
    [0xD6] = {"SALC",0, 0, NONE, NONE, NONE, NULL},
    [0xD7] = {"XLATB",0, 0, NONE, NONE, NONE, NULL},
    [0xd8] = { "FPU", 0, HAS_MODRM, NONE, NONE, NONE, NULL }, // D8 FPU，HAS_MODRM是必要的，要保证反汇编器能正确计算指令长度并跳到下一条指令
    [0xd9] = { "FPU", 0, HAS_MODRM, NONE, NONE, NONE, NULL }, 
    [0xda] = { "FPU", 0, HAS_MODRM, NONE, NONE, NONE, NULL }, 
    [0xdb] = { "FPU", 0, HAS_MODRM, NONE, NONE, NONE, NULL }, 
    [0xdc] = { "FPU", 0, HAS_MODRM, NONE, NONE, NONE, NULL }, 
    [0xdd] = { "FPU", 0, HAS_MODRM, NONE, NONE, NONE, NULL }, 
    [0xde] = { "FPU", 0, HAS_MODRM, NONE, NONE, NONE, NULL },
    [0xdf] = { "FPU", 0, HAS_MODRM, NONE, NONE, NONE, NULL }, 
    //0xE0 - 0xEF
    [0xe0] = {"LOOPNZ",0, 0, Jb, NONE, NONE, NULL},
    [0xe1] = {"LOOPZ",0, 0, Jb, NONE, NONE, NULL},
    [0xe2] = {"LOOP",0, 0, Jb, NONE, NONE, NULL},
    [0xe3] = {"JCXZ",0, 0, Jb, NONE, NONE, NULL},
    [0xe4] = {"IN",0, 0, OP_AL, Ib, NONE, NULL},
    [0xe5] = {"IN",0, 0, OP_rAX, Ib, NONE, NULL},
    [0xe6] = {"OUT",0, 0, Ib, OP_AL, NONE, NULL},
    [0xe7] = {"OUT",0, 0, Ib, OP_rAX, NONE, NULL},
    [0xe8] = {"CALL",0, 0, Jz, NONE, NONE, NULL},
    [0xe9] = {"JMP",0, 0,Jz , NONE , NONE , NULL},
    [0xea] = {"JMP FAR PTR",0, 0 , Ap , NONE , NONE , NULL},
    [0xeb] = {"JMP",0, 0 , Jb , NONE , NONE , NULL},
    [0xec] = {"IN",0, 0 , OP_AL , OP_DX , NONE , NULL},
    [0xed] = {"IN",0 , 0 , OP_rAX , OP_DX , NONE , NULL},
    [0xee] = {"OUT",0 , 0 , OP_DX , OP_AL , NONE , NULL},
	[0xef] = { "OUT",0 , 0 , OP_DX , OP_rAX , NONE , NULL },
    //0xF0 - 0xFF
    [0xf0] = {"LOCK",IS_PREFIX,0, NONE, NONE, NONE, NULL},
	[0xf1] = { "INT 1",0, 0, NONE, NONE, NONE, NULL },
    [0xf2] = {"REPNZ",IS_PREFIX, 0, NONE, NONE, NONE, NULL },
    [0xf3] = { "REP",   IS_PREFIX, 0, NONE, NONE, NONE, NULL },
    [0xf4] = { "HLT",   0, 0, NONE, NONE, NONE, NULL },
    [0xf5] = { "CMC",   0, 0, NONE, NONE, NONE, NULL },
    // Group 3 (TEST, NOT, NEG, MUL, IMUL, DIV, IDIV)
    // F6: Byte operands. F7: Word/Dword operands.
    // 操作数由 Group Table 定义，Opcode 表这里置为 NONE 避免冲突
    // 你的引擎需要能识别出 0xF6 使用 Group 3 的 Eb 版本，0xF7 使用 Ev 版本
    [0xf6] = { NULL, 0, HAS_MODRM, NONE , NONE, NONE, (GroupEntry*)group_tables[3] },
    [0xf7] = { NULL, 0, HAS_MODRM, NONE, NONE, NONE, (GroupEntry*)group_tables[17] },

    [0xf8] = { "CLC", 0, 0, NONE, NONE, NONE, NULL },
    [0xf9] = { "STC", 0, 0, NONE, NONE, NONE, NULL },
    [0xfa] = { "CLI", 0, 0, NONE, NONE, NONE, NULL },
    [0xfb] = { "STI", 0, 0, NONE, NONE, NONE, NULL },
    [0xfc] = { "CLD", 0, 0, NONE, NONE, NONE, NULL },
    [0xfd] = { "STD", 0, 0, NONE, NONE, NONE, NULL },

    // Group 4 (INC/DEC Byte)
    [0xfe] = { NULL, 0, HAS_MODRM, NONE, NONE, NONE, (GroupEntry*)group_tables[4] },
    // Group 5 (INC/DEC/CALL/JMP/PUSH Word/Dword)
    [0xff] = { NULL, 0, HAS_MODRM, NONE, NONE, NONE, (GroupEntry*)group_tables[5] },

    
    // ...
};

const OpcodeEntry two_byte_opcode_table[256] = {
    // 0x00 - 0x0F (部分系统指令，通常由Group 6/7处理，这里列出常见的独立指令)
    [0x05] = {"SYSCALL", 0, 0, NONE, NONE, NONE, NULL},
    [0x0B] = {"UD2", 0, 0, NONE, NONE, NONE, NULL}, // 定义未定义指令，用于触发异常

    // 0x10 - 0x1F (SIMD/SSE 很多在这里，反汇编引擎前期可以先跳过，这里只写常见的)
    [0x1F] = {"NOP", 0, HAS_MODRM, Ev, NONE, NONE, NULL}, // 多字节 NOP (Group 16)

    // 0x30 - 0x3F
    [0x31] = {"RDTSC", 0, 0, NONE, NONE, NONE, NULL}, // 读时间戳计数器

    // 0x40 - 0x4F: CMOVcc (条件传送) - 非常常见！编译器优化的最爱
    // 格式: CMOVcc Gv, Ev (寄存器 = 内存/寄存器)
    [0x40] = {"CMOVO",  0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x41] = {"CMOVNO", 0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x42] = {"CMOVB",  0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x43] = {"CMOVNB", 0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x44] = {"CMOVZ",  0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x45] = {"CMOVNZ", 0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x46] = {"CMOVBE", 0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x47] = {"CMOVA",  0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x48] = {"CMOVS",  0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x49] = {"CMOVNS", 0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x4a] = {"CMOVP",  0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x4b] = {"CMOVNP", 0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x4c] = {"CMOVL",  0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x4d] = {"CMOVNL", 0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x4e] = {"CMOVLE", 0, HAS_MODRM, Gv, Ev, NONE, NULL},
    [0x4f] = {"CMOVG",  0, HAS_MODRM, Gv, Ev, NONE, NULL},

    // 0x80 - 0x8F: Long Conditional Jumps 
    [0x80] = {"JO",  0, 0, Jz, NONE, NONE, NULL},
    [0x81] = {"JNO", 0, 0, Jz, NONE, NONE, NULL},
    [0x82] = {"JB",  0, 0, Jz, NONE, NONE, NULL},
    [0x83] = {"JNB", 0, 0, Jz, NONE, NONE, NULL},
    [0x84] = {"JZ",  0, 0, Jz, NONE, NONE, NULL},
    [0x85] = {"JNZ", 0, 0, Jz, NONE, NONE, NULL},
    [0x86] = {"JBE", 0, 0, Jz, NONE, NONE, NULL},
    [0x87] = {"JA",  0, 0, Jz, NONE, NONE, NULL},
    [0x88] = {"JS",  0, 0, Jz, NONE, NONE, NULL},
    [0x89] = {"JNS", 0, 0, Jz, NONE, NONE, NULL},
    [0x8a] = {"JP",  0, 0, Jz, NONE, NONE, NULL},
    [0x8b] = {"JNP", 0, 0, Jz, NONE, NONE, NULL},
    [0x8c] = {"JL",  0, 0, Jz, NONE, NONE, NULL},
    [0x8d] = {"JNL", 0, 0, Jz, NONE, NONE, NULL},
    [0x8e] = {"JLE", 0, 0, Jz, NONE, NONE, NULL},
    [0x8f] = {"JG",  0, 0, Jz, NONE, NONE, NULL},

    // 0x90 - 0x9F: SETcc (条件置位) - 将条件结果写入一个字节
    // 格式: SETcc Eb (注意：操作数是Eb，写入8位寄存器或内存)
    [0x90] = {"SETO",  0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x91] = {"SETNO", 0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x92] = {"SETB",  0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x93] = {"SETNB", 0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x94] = {"SETZ",  0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x95] = {"SETNZ", 0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x96] = {"SETBE", 0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x97] = {"SETA",  0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x98] = {"SETS",  0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x99] = {"SETNS", 0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x9a] = {"SETP",  0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x9b] = {"SETNP", 0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x9c] = {"SETL",  0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x9d] = {"SETNL", 0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x9e] = {"SETLE", 0, HAS_MODRM, Eb, NONE, NONE, NULL},
    [0x9f] = {"SETG",  0, HAS_MODRM, Eb, NONE, NONE, NULL},

    // 0xA0 - 0xAF: 栈段操作、位测试、双操作数乘法
    [0xa0] = {"PUSH",  0, 0, OP_FS, NONE, NONE, NULL},
    [0xa1] = {"POP",   0, 0, OP_FS, NONE, NONE, NULL},
    [0xa2] = {"CPUID", 0, 0, NONE,  NONE, NONE, NULL},
    [0xa3] = {"BT",    0, HAS_MODRM, Ev, Gv, NONE, NULL}, // Bit Test
    [0xa4] = {"SHLD",  0, HAS_MODRM, Ev, Gv, Ib,   NULL}, // 双精度左移 (立即数)
    [0xa5] = {"SHLD",  0, HAS_MODRM, Ev, Gv, OP_CL,NULL}, // 双精度左移 (CL)
    [0xa8] = {"PUSH",  0, 0, OP_GS, NONE, NONE, NULL},
    [0xa9] = {"POP",   0, 0, OP_GS, NONE, NONE, NULL},
    [0xac] = {"SHRD",  0, HAS_MODRM, Ev, Gv, Ib,   NULL}, // 双精度右移 (立即数)
    [0xad] = {"SHRD",  0, HAS_MODRM, Ev, Gv, OP_CL,NULL}, // 双精度右移 (CL)
    [0xaf] = {"IMUL",  0, HAS_MODRM, Gv, Ev, NONE, NULL}, // 这里的IMUL是双操作数版本：reg = reg * r/m

    // 0xB0 - 0xBF: 扩展移动、位扫描 (非常常见)
    [0xb0] = {"CMPXCHG", 0, HAS_MODRM, Eb, Gb, NONE, NULL}, // 比较并交换 Byte
    [0xb1] = {"CMPXCHG", 0, HAS_MODRM, Ev, Gv, NONE, NULL}, // 比较并交换 Word/Dword
    [0xb6] = {"MOVZX",   0, HAS_MODRM, Gv, Eb, NONE, NULL}, // 零扩展移动 Byte -> Word/Dword
    [0xb7] = {"MOVZX",   0, HAS_MODRM, Gv, Ew, NONE, NULL}, // 零扩展移动 Word -> Dword
    [0xbc] = {"BSF",     0, HAS_MODRM, Gv, Ev, NONE, NULL}, // Bit Scan Forward
    [0xbd] = {"BSR",     0, HAS_MODRM, Gv, Ev, NONE, NULL}, // Bit Scan Reverse
    [0xbe] = {"MOVSX",   0, HAS_MODRM, Gv, Eb, NONE, NULL}, // 符号扩展移动 Byte -> Word/Dword
    [0xbf] = {"MOVSX",   0, HAS_MODRM, Gv, Ew, NONE, NULL}, // 符号扩展移动 Word -> Dword

    // 0xC0 - 0xC7: XADD
    [0xc0] = {"XADD", 0, HAS_MODRM, Eb, Gb, NONE, NULL},
    [0xc1] = {"XADD", 0, HAS_MODRM, Ev, Gv, NONE, NULL},

    // 0xC8 - 0xCF: BSWAP (字节交换)
    // 类似于 Opcode Map 0x50-0x57 的 PUSH/POP，这里也是嵌入寄存器编号的
    [0xc8] = {"BSWAP", 0, 0, OP_rAX, NONE, NONE, NULL},
    [0xc9] = {"BSWAP", 0, 0, OP_rCX, NONE, NONE, NULL},
    [0xca] = {"BSWAP", 0, 0, OP_rDX, NONE, NONE, NULL},
    [0xcb] = {"BSWAP", 0, 0, OP_rBX, NONE, NONE, NULL},
    [0xcc] = {"BSWAP", 0, 0, OP_rSP, NONE, NONE, NULL},
    [0xcd] = {"BSWAP", 0, 0, OP_rBP, NONE, NONE, NULL},
    [0xce] = {"BSWAP", 0, 0, OP_rSI, NONE, NONE, NULL},
    [0xcf] = {"BSWAP", 0, 0, OP_rDI, NONE, NONE, NULL},
};

//寄存器名称
const char* reg8[] = { "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH" };
const char* reg16[] = { "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI" };
const char* reg32[] = { "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI" };
//段寄存器名称
const char* SEG_REGS[] = {  "ES", "CS", "SS", "DS", "FS", "GS", "???", "???"};
//16位寻址模式下的rm字段对应的寻址方式
const char* rm16_str[] = { "BX+SI", "BX+DI", "BP+SI", "BP+DI", "SI", "DI", "BP", "BX" };

const char* GetRegisterName(int reg_size, int reg_index) { //段寄存器看作size1
    switch (reg_size) {
        case 1:
            return  SEG_REGS[reg_index];
        case 8:
            return reg8[reg_index];
        case 16:
            return reg16[reg_index];
        case 32:
            return reg32[reg_index];
        // 添加其他寄存器类型的处理
        default:
            return "???";
    }
}

static bool IsImmediate(OperandType type) {
    return (type == Ib || type == Iw || type == Iz || type == Iv || 
            type == Jb || type == Jz || type == Ap || type == Ob || type == Ov);
}

// 读取一个字节
static uint8_t ReadByte(DecodeContext* ctx) {
    if (ctx->pos >= ctx->max_len) return 0;
    return ctx->buffer[ctx->pos++];
}
// 读取一个字
static inline uint16_t ReadWord(DecodeContext* ctx) {
    if (ctx->pos + 2 > ctx->max_len) return 0; // 一次性检查
    uint16_t val = *(uint16_t*)(ctx->buffer + ctx->pos);
    ctx->pos += 2;
    return val;
}
// 读取一个双字
static inline uint32_t ReadDword(DecodeContext* ctx) {
    if (ctx->pos + 4 > ctx->max_len) return 0; // 一次性检查
    uint32_t val = *(uint32_t*)(ctx->buffer + ctx->pos);
    ctx->pos += 4;
    return val;
}

// 解析前缀
// 前缀分为4组：
// 1. 锁/重复前缀 (LOCK, REP/REPNE)
// 2. 段覆盖前缀 (CS, SS, DS, ES, FS, GS)
// 3. 操作数大小覆盖 (0x66) - 切换 16/32 位操作数
// 4. 地址大小覆盖 (0x67) - 切换 16/32 位地址模式
void ParsePrefixes(DecodeContext* ctx) {
    bool has_prefix = true;
    while (has_prefix && ctx->pos < ctx->max_len) {
        uint8_t byte = ctx->buffer[ctx->pos];
        switch (byte) {
            case 0xF0: ctx->pfx_lock = true; ctx->pos++; break;
            case 0xF2: ctx->pfx_repne = true; ctx->pos++; break;
            case 0xF3: ctx->pfx_rep = true; ctx->pos++; break;
            case 0x66: ctx->pfx_op_size = byte; ctx->pos++; break;
            case 0x67: ctx->pfx_addr_size = byte; ctx->pos++; break;
            case 0x26: case 0x2E: case 0x36: case 0x3E:
            case 0x64: case 0x65:
                ctx->pfx_segment = byte; ctx->pos++; break;
            default: has_prefix = false; break;
        }
    }
}

// 解析 ModR/M 字节
// ModR/M 格式: [Mod:2][Reg/Opcode:3][R/M:3]
// Mod: 寻址模式 (00=内存, 01=内存+disp8, 10=内存+disp32, 11=寄存器)
// Reg: 寄存器索引 或 Opcode 扩展 (取决于指令)
// R/M: 寄存器索引 或 内存寻址方式
void ParseModRM(DecodeContext* ctx) {
    ctx->modrm = ReadByte(ctx);
    ctx->mod = (ctx->modrm >> 6) & 0x3;
    ctx->reg = (ctx->modrm >> 3) & 0x7;
    ctx->rm = ctx->modrm & 0x7;
}

// 解析 SIB 字节
// SIB 格式: [Scale:2][Index:3][Base:3]
// 用于复杂的内存寻址: [Base + Index * (2^Scale) + Disp]
// 仅在 ModR/M 的 R/M 字段为 100 (ESP) 时出现 (32位模式下)
void ParseSIB(DecodeContext* ctx) {
    ctx->sib = ReadByte(ctx);
    ctx->scale = (ctx->sib >> 6) & 0x3;
    ctx->index = (ctx->sib >> 3) & 0x7;
    ctx->base = ctx->sib & 0x7;
    ctx->has_sib = true;
}

// 解析位移
void ParseDisplacement(DecodeContext* ctx) {
    int addr_size = (ctx->pfx_addr_size == 0x67) ? 16 : 32;
    
    if (addr_size == 32) {
        // 32位寻址
        if (ctx->mod == 0 && ctx->rm == 5) { //rm->ebp
            // Mod=00, R/M=101 (EBP) 是特殊情况，表示仅有32位位移 [disp32]，没有基址寄存器
            // disp32
            ctx->disp = (int32_t)ReadDword(ctx);
            ctx->disp_len = 4;
        } else if (ctx->mod == 1) {
            // Mod=01: [Reg + disp8]
            // disp8
            ctx->disp = (int8_t)ReadByte(ctx);
            ctx->disp_len = 1;
        } else if (ctx->mod == 2) {
            // Mod=10: [Reg + disp32]
            // disp32
            ctx->disp = (int32_t)ReadDword(ctx);
            ctx->disp_len = 4;
        } else if (ctx->has_sib && ctx->mod == 0 && ctx->base == 5) { 
            // SIB mod=0 base=5 -> disp32 Intel 规定这不是 [EBP + Index*Scale]，而是 [disp32 + Index*Scale]。也就是说，EBP 被干掉了，替换成了一个 32 位位移。
            // 这是一个非常容易出错的角落情况
            ctx->disp = (int32_t)ReadDword(ctx);
            ctx->disp_len = 4;
        }
    } else {
        // 16位寻址 (比较少见，但在实模式或使用 0x67 前缀时出现)
        if (ctx->mod == 0 && ctx->rm == 6) {
            // Mod=00, R/M=110 (BP) 是特殊情况，表示 [disp16]
            ctx->disp = (int16_t)ReadWord(ctx);
            ctx->disp_len = 2;
        } else if (ctx->mod == 1) {
            ctx->disp = (int8_t)ReadByte(ctx);
            ctx->disp_len = 1;
        } else if (ctx->mod == 2) {
            ctx->disp = (int16_t)ReadWord(ctx);
            ctx->disp_len = 2;
        }
    }
}

// 解析立即数
void ParseImmediate(DecodeContext* ctx, OperandType type, int imm_index) {
    int op_size = (ctx->pfx_op_size == 0x66) ? 16 : 32;
    int addr_size = (ctx->pfx_addr_size == 0x67) ? 16 : 32;
    
    int64_t* p_imm = (imm_index == 0) ? &ctx->imm : &ctx->imm2;
    int* p_imm_len = (imm_index == 0) ? &ctx->imm_len : &ctx->imm2_len;

    switch (type) {
        case Ib:
            *p_imm = (int8_t)ReadByte(ctx);
            *p_imm_len = 1;
            break;
        case Iw:
            *p_imm = (int16_t)ReadWord(ctx);
            *p_imm_len = 2;
            break;
        case Iz:
            if (op_size == 16) {
                *p_imm = (int16_t)ReadWord(ctx);
                *p_imm_len = 2;
            } else {
                *p_imm = (int32_t)ReadDword(ctx);
                *p_imm_len = 4;
            }
            break;
        case Iv:
            if (op_size == 16) {
                *p_imm = (int16_t)ReadWord(ctx);
                *p_imm_len = 2;
            } else {
                *p_imm = (int32_t)ReadDword(ctx);
                *p_imm_len = 4;
            }
            break;
        case Jb:
            *p_imm = (int8_t)ReadByte(ctx);
            *p_imm_len = 1;
            break;
        case Jz:
            if (op_size == 16) {
                *p_imm = (int16_t)ReadWord(ctx);
                *p_imm_len = 2;
            } else {
                *p_imm = (int32_t)ReadDword(ctx);
                *p_imm_len = 4;
            }
            break;
        case Ap:
            // 远指针：偏移+段选择子 (JMP FAR / CALL FAR)
            // 必须分开读取以确保顺序：先读偏移(Offset)，后读段(Segment)
            if (op_size == 16) {
                uint32_t offset = ReadWord(ctx);
                uint32_t segment = ReadWord(ctx);
                *p_imm = offset | (segment << 16);
                *p_imm_len = 4;
            }
            else {
                uint64_t offset = ReadDword(ctx);
                uint64_t segment = ReadWord(ctx);
                *p_imm = offset | (segment << 32);
                *p_imm_len = 6;
            }
            break;
        case Ob:
        case Ov:
            if (addr_size == 16) {
                *p_imm = ReadWord(ctx);
                *p_imm_len = 2;
            } else {
                *p_imm = ReadDword(ctx);
                *p_imm_len = 4;
            }
            break;
        default:
            break;
    }
}

// 格式化 ModR/M 操作数
void FormatModRM(DecodeContext* ctx, char* buf, int size, OperandType type) {
    int op_size = (ctx->pfx_op_size == 0x66) ? 16 : 32;
    int addr_size = (ctx->pfx_addr_size == 0x67) ? 16 : 32;
    
    // 确定操作数大小
    int operand_size = 32;
    if (type == Eb || type == Gb) operand_size = 8;
    else if (type == Ew || type == Gw) operand_size = 16;
    else if (type == Ev || type == Gv || type == Gz) operand_size = op_size;
    
    // 如果是寄存器
    if (ctx->mod == 3) {
        const char* reg_name = GetRegisterName(operand_size, ctx->rm);
        snprintf(buf, size, "%s", reg_name);
        return;
    }
    
    // 内存操作数
    char size_prefix[16] = "";
    if (type == Eb || type == Gb) strcpy(size_prefix, "BYTE PTR ");
    else if (type == Ew || type == Gw) strcpy(size_prefix, "WORD PTR ");
    else if (type == Ev || type == Gv || type == Gz) {
        if (op_size == 16) strcpy(size_prefix, "WORD PTR ");
        else strcpy(size_prefix, "DWORD PTR ");
    }
    else if (type == M || type == Mv) {
        if (op_size == 16) strcpy(size_prefix, "WORD PTR ");
        else strcpy(size_prefix, "DWORD PTR ");
    }
    else if (type == Mp) {
        // Mp: 包含远指针的内存操作数
        // 大小由操作数大小 (0x66) 决定，而不是地址大小 (0x67)
        // 16位操作数: 16位偏移 + 16位段 = 32位 (DWORD)
        // 32位操作数: 32位偏移 + 16位段 = 48位 (FWORD)
        if (op_size == 16) strcpy(size_prefix, "DWORD PTR ");
        else strcpy(size_prefix, "FWORD PTR ");
    }
    else if (type == Ma) {
        if (op_size == 16) strcpy(size_prefix, "DWORD PTR ");
        else strcpy(size_prefix, "QWORD PTR ");
    }
    else if (type == M_F32 || type == M_I32) strcpy(size_prefix, "DWORD PTR ");
    else if (type == M_F64 || type == M_I64) strcpy(size_prefix, "QWORD PTR ");
    else if (type == M_F80 || type == M_BCD) strcpy(size_prefix, "TBYTE PTR ");
    else if (type == M_I16 || type == M_SW || type == M_CW) strcpy(size_prefix, "WORD PTR ");
    else if (type == M_ENV) strcpy(size_prefix, ""); // Environment size varies
    else if (type == M_STATE) strcpy(size_prefix, ""); // State size varies
    
    // 处理段前缀
    char seg_prefix[8] = "";
    if (ctx->pfx_segment) {
        // 如果有显式的段前缀，直接使用
        switch (ctx->pfx_segment) {
            case 0x26: strcpy(seg_prefix, "ES:"); break;
            case 0x2E: strcpy(seg_prefix, "CS:"); break;
            case 0x36: strcpy(seg_prefix, "SS:"); break;
            case 0x3E: strcpy(seg_prefix, "DS:"); break;
            case 0x64: strcpy(seg_prefix, "FS:"); break;
            case 0x65: strcpy(seg_prefix, "GS:"); break;
            default: break;
        }
    } else {
        // 如果没有段前缀，根据基址寄存器推断默认段寄存器
        // 规则：基址是 ESP 或 EBP (或 BP) 时，默认使用 SS，否则使用 DS
        bool use_ss = false;
        if (addr_size == 32) {
            if (ctx->rm == 4 && ctx->has_sib) {
                if (ctx->base == 4) use_ss = true; // ESP base -> SS
                else if (ctx->base == 5 && ctx->mod != 0) use_ss = true; // EBP base -> SS (注意 Mod=0时 Base=5是disp32，不是EBP)
            } else if (ctx->rm == 5 && ctx->mod != 0) {
                use_ss = true; // EBP base -> SS
            }
        } else {
            if (ctx->rm == 2 || ctx->rm == 3) use_ss = true; // BP base -> SS
            else if (ctx->rm == 6 && ctx->mod != 0) use_ss = true; // BP base -> SS
        }
        strcpy(seg_prefix, use_ss ? "SS:" : "DS:");
    }

    char addr_buf[64] = "";
    
    if (addr_size == 32) {
        // 32位寻址
        if (ctx->mod == 0 && ctx->rm == 5) {
            snprintf(addr_buf, sizeof(addr_buf), "[0x%08X]", (uint32_t)ctx->disp);
        } else if (ctx->rm == 4) {
            // 有SIB字节
            if (ctx->has_sib) {
                char base_str[16] = ""; 
                char index_str[32] = "";
                char disp_str[16] = "";
                
				if (!(ctx->base == 5 && ctx->mod == 0)) {  //不是这种特殊情况则显示base
                    strcpy(base_str, GetRegisterName(32, ctx->base));
                }
                
				if (ctx->index != 4) { // ESP不能作为索引，所以index=4 表示没有索引寄存器
                    int scale_val = 1 << ctx->scale;
                    if (scale_val == 1)
                        snprintf(index_str, sizeof(index_str), "+%s", GetRegisterName(32, ctx->index));
                    else
                        snprintf(index_str, sizeof(index_str), "+%s*%d", GetRegisterName(32, ctx->index), scale_val);
                }
                
                if (ctx->disp_len != 0) {
                    if (ctx->disp >= 0)
                        snprintf(disp_str, sizeof(disp_str), "+0x%X", (uint32_t)ctx->disp);
                    else
                        snprintf(disp_str, sizeof(disp_str), "-0x%X", (uint32_t)(-ctx->disp));
                }
                
                snprintf(addr_buf, sizeof(addr_buf), "[%s%s%s]", base_str, index_str, disp_str);
            }
        } else {
            // 普通寻址
            const char* base_reg = GetRegisterName(32, ctx->rm);
            if (ctx->disp > 0) {
                snprintf(addr_buf, sizeof(addr_buf), "[%s+0x%X]", base_reg, (uint32_t)ctx->disp);
            } else if (ctx->disp < 0) {
                snprintf(addr_buf, sizeof(addr_buf), "[%s-0x%X]", base_reg, (uint32_t)(-ctx->disp));
			}else {  // disp == 0
                snprintf(addr_buf, sizeof(addr_buf), "[%s]", base_reg);
            }
        }
    } else {
        // 16位寻址
        if (ctx->mod == 0 && ctx->rm == 6) {
            snprintf(addr_buf, sizeof(addr_buf), "[0x%X]", (uint16_t)ctx->disp);
        } else {
            
            const char* base_reg = rm16_str[ctx->rm];

            if (ctx->disp != 0) {
                if (ctx->disp > 0)
                    snprintf(addr_buf, sizeof(addr_buf), "[%s+0x%X]", base_reg, (uint16_t)ctx->disp);
                else
                    snprintf(addr_buf, sizeof(addr_buf), "[%s-0x%X]", base_reg, (uint16_t)(-ctx->disp));
            } else {
                snprintf(addr_buf, sizeof(addr_buf), "[%s]", base_reg);
            }
        }
    }
    
    snprintf(buf, size, "%s%s%s", size_prefix, seg_prefix, addr_buf);
}

// 格式化操作数
void FormatOperand(DecodeContext* ctx, char* buf, int size, OperandType type, int* imm_index) {
    int op_size = (ctx->pfx_op_size == 0x66) ? 16 : 32;
    
    int64_t val = 0;
    if (IsImmediate(type)) {
        val = (*imm_index == 0) ? ctx->imm : ctx->imm2;
        (*imm_index)++;
    }

    switch (type) {
        case NONE:
            buf[0] = '\0';
            break;
            
        // 寄存器操作数
        case Gb:
            snprintf(buf, size, "%s", GetRegisterName(8, ctx->reg));
            break;
        case Gw:
            snprintf(buf, size, "%s", GetRegisterName(16, ctx->reg));
            break;
        case Gv:
        case Gz:
            snprintf(buf, size, "%s", GetRegisterName(op_size, ctx->reg));
            break;
        case Sw:
            snprintf(buf, size, "%s", GetRegisterName(1, ctx->reg));
            break;
            
        // 内存/寄注册操作数
        case Eb:
        case Ew:
        case Ev:
        case M:
        case Mv:
        case Mp:
        case Ma:
            FormatModRM(ctx, buf, size, type);
            break;
            
        // 立即数
        case Ib:
            snprintf(buf, size, "0x%X", (uint8_t)val);
            break;
        case Iw:
            snprintf(buf, size, "0x%X", (uint16_t)val);
            break;
        case Iz:
        case Iv:
            if (op_size == 16)
                snprintf(buf, size, "0x%X", (uint16_t)val);
            else
                snprintf(buf, size, "0x%X", (uint32_t)val);
            break;
        case Ap:
        {
            uint16_t seg;
            uint32_t off;
            if (op_size == 16) {
                // 16:16 格式
                off = val & 0xFFFF;
                seg = (val >> 16) & 0xFFFF;
                snprintf(buf, size, "0x%04X:0x%04X", seg, off);
            }
            else {
                // 16:32 格式
                off = (uint32_t)(val & 0xFFFFFFFF);
                seg = (uint16_t)((val >> 32) & 0xFFFF);
                snprintf(buf, size, "0x%04X:0x%08X", seg, off);
            }
            break;
        }
        // 相对跳转
        case Jb:
        case Jz:
            snprintf(buf, size, "0x%08X", (uint32_t)(ctx->eip + ctx->pos + val));
            break;

        case Ob:
        case Ov:
            {
                char size_prefix[16] = "";
                if (type == Ob) strcpy(size_prefix, "BYTE PTR ");
                else if (type == Ov) {
                    if (op_size == 16) strcpy(size_prefix, "WORD PTR ");
                    else strcpy(size_prefix, "DWORD PTR ");
                }

                char seg_prefix[8] = "DS:";
                if (ctx->pfx_segment) {
                    switch (ctx->pfx_segment) {
                        case 0x26: strcpy(seg_prefix, "ES:"); break;
                        case 0x2E: strcpy(seg_prefix, "CS:"); break;
                        case 0x36: strcpy(seg_prefix, "SS:"); break;
                        case 0x3E: strcpy(seg_prefix, "DS:"); break;
                        case 0x64: strcpy(seg_prefix, "FS:"); break;
                        case 0x65: strcpy(seg_prefix, "GS:"); break;
                    }
                }

                int addr_size = (ctx->pfx_addr_size == 0x67) ? 16 : 32;

                if (addr_size == 16) {
                    snprintf(buf, size, "%s%s[0x%X]", size_prefix, seg_prefix, (uint16_t)val);
                } else {
                    snprintf(buf, size, "%s%s[0x%08X]", size_prefix, seg_prefix, (uint32_t)val);
                }
            }
            break;
            
        // 固定寄存器
        case OP_AL: snprintf(buf, size, "AL"); break;
        case OP_CL: snprintf(buf, size, "CL"); break;
        case OP_DL: snprintf(buf, size, "DL"); break;
        case OP_BL: snprintf(buf, size, "BL"); break;
        case OP_AH: snprintf(buf, size, "AH"); break;
        case OP_CH: snprintf(buf, size, "CH"); break;
        case OP_DH: snprintf(buf, size, "DH"); break;
        case OP_BH: snprintf(buf, size, "BH"); break;
        case OP_DX: snprintf(buf, size, "DX"); break;
        case OP_rAX: snprintf(buf, size, "%s", GetRegisterName(op_size, 0)); break;
        case OP_rCX: snprintf(buf, size, "%s", GetRegisterName(op_size, 1)); break;
        case OP_rDX: snprintf(buf, size, "%s", GetRegisterName(op_size, 2)); break;
        case OP_rBX: snprintf(buf, size, "%s", GetRegisterName(op_size, 3)); break;
        case OP_rSP: snprintf(buf, size, "%s", GetRegisterName(op_size, 4)); break;
        case OP_rBP: snprintf(buf, size, "%s", GetRegisterName(op_size, 5)); break;
        case OP_rSI: snprintf(buf, size, "%s", GetRegisterName(op_size, 6)); break;
        case OP_rDI: snprintf(buf, size, "%s", GetRegisterName(op_size, 7)); break;
        case OP_ES: snprintf(buf, size, "ES"); break;
        case OP_CS: snprintf(buf, size, "CS"); break;
        case OP_SS: snprintf(buf, size, "SS"); break;
        case OP_DS: snprintf(buf, size, "DS"); break;
        case OP_ONE: snprintf(buf, size, "1"); break;
        
        case OP_ST0: snprintf(buf, size, "ST(0)"); break;
        case OP_STi: snprintf(buf, size, "ST(%d)", ctx->rm); break;

        case M_F32:
        case M_F64:
        case M_F80:
        case M_I16:
        case M_I32:
        case M_I64:
        case M_BCD:
        case M_ENV:
        case M_SW:
        case M_CW:
        case M_STATE:
            FormatModRM(ctx, buf, size, type);
            break;
            
        default:
            snprintf(buf, size, "???");
            break;
    }
}

void ParseFPU(DecodeContext* ctx) {
    uint8_t op = ctx->opcode;
    uint8_t mod = ctx->mod;
    uint8_t reg = ctx->reg;
    uint8_t rm = ctx->rm;

    // Default
    ctx->entry.mnemonic = "FPU?";
    ctx->entry.op1 = NONE;
    ctx->entry.op2 = NONE;
    ctx->entry.op3 = NONE;

    switch (op) {
        case 0xD8:
            if (mod != 3) {
                ctx->entry.op1 = M_F32;
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FADD"; break;
                    case 1: ctx->entry.mnemonic = "FMUL"; break;
                    case 2: ctx->entry.mnemonic = "FCOM"; break;
                    case 3: ctx->entry.mnemonic = "FCOMP"; break;
                    case 4: ctx->entry.mnemonic = "FSUB"; break;
                    case 5: ctx->entry.mnemonic = "FSUBR"; break;
                    case 6: ctx->entry.mnemonic = "FDIV"; break;
                    case 7: ctx->entry.mnemonic = "FDIVR"; break;
                }
            } else {
                ctx->entry.op1 = OP_ST0;
                ctx->entry.op2 = OP_STi;
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FADD"; break;
                    case 1: ctx->entry.mnemonic = "FMUL"; break;
                    case 2: ctx->entry.mnemonic = "FCOM"; ctx->entry.op1 = OP_STi; ctx->entry.op2 = NONE; break;
                    case 3: ctx->entry.mnemonic = "FCOMP"; ctx->entry.op1 = OP_STi; ctx->entry.op2 = NONE; break;
                    case 4: ctx->entry.mnemonic = "FSUB"; break;
                    case 5: ctx->entry.mnemonic = "FSUBR"; break;
                    case 6: ctx->entry.mnemonic = "FDIV"; break;
                    case 7: ctx->entry.mnemonic = "FDIVR"; break;
                }
            }
            break;
        case 0xD9:
            if (mod != 3) {
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FLD"; ctx->entry.op1 = M_F32; break;
                    case 2: ctx->entry.mnemonic = "FST"; ctx->entry.op1 = M_F32; break;
                    case 3: ctx->entry.mnemonic = "FSTP"; ctx->entry.op1 = M_F32; break;
                    case 4: ctx->entry.mnemonic = "FLDENV"; ctx->entry.op1 = M_ENV; break;
                    case 5: ctx->entry.mnemonic = "FLDCW"; ctx->entry.op1 = M_CW; break;
                    case 6: ctx->entry.mnemonic = "FNSTENV"; ctx->entry.op1 = M_ENV; break;
                    case 7: ctx->entry.mnemonic = "FNSTCW"; ctx->entry.op1 = M_CW; break;
                }
            } else {
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FLD"; ctx->entry.op1 = OP_STi; break;
                    case 1: ctx->entry.mnemonic = "FXCH"; ctx->entry.op1 = OP_STi; break;
                    case 2: 
                        if (rm == 0) ctx->entry.mnemonic = "FNOP";
                        else { ctx->entry.mnemonic = "FSTP"; ctx->entry.op1 = OP_STi; }
                        break;
                    case 4:
                        switch (rm) {
                            case 0: ctx->entry.mnemonic = "FCHS"; break;
                            case 1: ctx->entry.mnemonic = "FABS"; break;
                            case 4: ctx->entry.mnemonic = "FTST"; break;
                            case 5: ctx->entry.mnemonic = "FXAM"; break;
                        }
                        break;
                    case 5:
                        switch (rm) {
                            case 0: ctx->entry.mnemonic = "FLD1"; break;
                            case 1: ctx->entry.mnemonic = "FLDL2T"; break;
                            case 2: ctx->entry.mnemonic = "FLDL2E"; break;
                            case 3: ctx->entry.mnemonic = "FLDPI"; break;
                            case 4: ctx->entry.mnemonic = "FLDLG2"; break;
                            case 5: ctx->entry.mnemonic = "FLDLN2"; break;
                            case 6: ctx->entry.mnemonic = "FLDZ"; break;
                        }
                        break;
                    case 6:
                        if (rm == 0) ctx->entry.mnemonic = "F2XM1";
                        else if (rm == 1) ctx->entry.mnemonic = "FYL2X";
                        else if (rm == 2) ctx->entry.mnemonic = "FPTAN";
                        else if (rm == 3) ctx->entry.mnemonic = "FPATAN";
                        else if (rm == 4) ctx->entry.mnemonic = "FXTRACT";
                        else if (rm == 5) ctx->entry.mnemonic = "FPREM1";
                        else if (rm == 6) ctx->entry.mnemonic = "FDECSTP";
                        else if (rm == 7) ctx->entry.mnemonic = "FINCSTP";
                        break;
                    case 7:
                        if (rm == 0) ctx->entry.mnemonic = "FPREM";
                        else if (rm == 1) ctx->entry.mnemonic = "FYL2XP1";
                        else if (rm == 2) ctx->entry.mnemonic = "FSQRT";
                        else if (rm == 3) ctx->entry.mnemonic = "FSINCOS";
                        else if (rm == 4) ctx->entry.mnemonic = "FRNDINT";
                        else if (rm == 5) ctx->entry.mnemonic = "FSCALE";
                        else if (rm == 6) ctx->entry.mnemonic = "FSIN";
                        else if (rm == 7) ctx->entry.mnemonic = "FCOS";
                        break;
                }
            }
            break;
        case 0xDA:
            if (mod != 3) {
                ctx->entry.op1 = M_I32;
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FIADD"; break;
                    case 1: ctx->entry.mnemonic = "FIMUL"; break;
                    case 2: ctx->entry.mnemonic = "FICOM"; break;
                    case 3: ctx->entry.mnemonic = "FICOMP"; break;
                    case 4: ctx->entry.mnemonic = "FISUB"; break;
                    case 5: ctx->entry.mnemonic = "FISUBR"; break;
                    case 6: ctx->entry.mnemonic = "FIDIV"; break;
                    case 7: ctx->entry.mnemonic = "FIDIVR"; break;
                }
            } else {
                if (reg == 5 && rm == 1) ctx->entry.mnemonic = "FUCOMPP";
                else {
                    ctx->entry.op1 = OP_ST0;
                    ctx->entry.op2 = OP_STi;
                    switch (reg) {
                        case 0: ctx->entry.mnemonic = "FCMOVB"; break;
                        case 1: ctx->entry.mnemonic = "FCMOVE"; break;
                        case 2: ctx->entry.mnemonic = "FCMOVBE"; break;
                        case 3: ctx->entry.mnemonic = "FCMOVU"; break;
                    }
                }
            }
            break;
        case 0xDB:
            if (mod != 3) {
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FILD"; ctx->entry.op1 = M_I32; break;
                    case 1: ctx->entry.mnemonic = "FISTTP"; ctx->entry.op1 = M_I32; break;
                    case 2: ctx->entry.mnemonic = "FIST"; ctx->entry.op1 = M_I32; break;
                    case 3: ctx->entry.mnemonic = "FISTP"; ctx->entry.op1 = M_I32; break;
                    case 5: ctx->entry.mnemonic = "FLD"; ctx->entry.op1 = M_F80; break;
                    case 7: ctx->entry.mnemonic = "FSTP"; ctx->entry.op1 = M_F80; break;
                }
            } else {
                if (reg == 4) {
                    if (rm == 2) ctx->entry.mnemonic = "FCLEX";
                    else if (rm == 3) ctx->entry.mnemonic = "FINIT";
                } else {
                    ctx->entry.op1 = OP_ST0;
                    ctx->entry.op2 = OP_STi;
                    switch (reg) {
                        case 0: ctx->entry.mnemonic = "FCMOVNB"; break;
                        case 1: ctx->entry.mnemonic = "FCMOVNE"; break;
                        case 2: ctx->entry.mnemonic = "FCMOVNBE"; break;
                        case 3: ctx->entry.mnemonic = "FCMOVNU"; break;
                        case 5: ctx->entry.mnemonic = "FUCOMI"; break;
                        case 6: ctx->entry.mnemonic = "FCOMI"; break;
                    }
                }
            }
            break;
        case 0xDC:
            if (mod != 3) {
                ctx->entry.op1 = M_F64;
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FADD"; break;
                    case 1: ctx->entry.mnemonic = "FMUL"; break;
                    case 2: ctx->entry.mnemonic = "FCOM"; break;
                    case 3: ctx->entry.mnemonic = "FCOMP"; break;
                    case 4: ctx->entry.mnemonic = "FSUB"; break;
                    case 5: ctx->entry.mnemonic = "FSUBR"; break;
                    case 6: ctx->entry.mnemonic = "FDIV"; break;
                    case 7: ctx->entry.mnemonic = "FDIVR"; break;
                }
            } else {
                ctx->entry.op1 = OP_STi;
                ctx->entry.op2 = OP_ST0;
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FADD"; break;
                    case 1: ctx->entry.mnemonic = "FMUL"; break;
                    case 4: ctx->entry.mnemonic = "FSUBR"; break;
                    case 5: ctx->entry.mnemonic = "FSUB"; break;
                    case 6: ctx->entry.mnemonic = "FDIVR"; break;
                    case 7: ctx->entry.mnemonic = "FDIV"; break;
                }
            }
            break;
        case 0xDD:
            if (mod != 3) {
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FLD"; ctx->entry.op1 = M_F64; break;
                    case 1: ctx->entry.mnemonic = "FISTTP"; ctx->entry.op1 = M_I64; break;
                    case 2: ctx->entry.mnemonic = "FST"; ctx->entry.op1 = M_F64; break;
                    case 3: ctx->entry.mnemonic = "FSTP"; ctx->entry.op1 = M_F64; break;
                    case 4: ctx->entry.mnemonic = "FRSTOR"; ctx->entry.op1 = M_STATE; break;
                    case 6: ctx->entry.mnemonic = "FNSAVE"; ctx->entry.op1 = M_STATE; break;
                    case 7: ctx->entry.mnemonic = "FNSTSW"; ctx->entry.op1 = M_SW; break;
                }
            } else {
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FFREE"; ctx->entry.op1 = OP_STi; break;
                    case 1: ctx->entry.mnemonic = "FXCH"; ctx->entry.op1 = OP_STi; break;
                    case 2: ctx->entry.mnemonic = "FST"; ctx->entry.op1 = OP_STi; break;
                    case 3: ctx->entry.mnemonic = "FSTP"; ctx->entry.op1 = OP_STi; break;
                    case 4: ctx->entry.mnemonic = "FUCOM"; ctx->entry.op1 = OP_STi; break;
                    case 5: ctx->entry.mnemonic = "FUCOMP"; ctx->entry.op1 = OP_STi; break;
                }
            }
            break;
        case 0xDE:
            if (mod != 3) {
                ctx->entry.op1 = M_I16;
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FIADD"; break;
                    case 1: ctx->entry.mnemonic = "FIMUL"; break;
                    case 2: ctx->entry.mnemonic = "FICOM"; break;
                    case 3: ctx->entry.mnemonic = "FICOMP"; break;
                    case 4: ctx->entry.mnemonic = "FISUB"; break;
                    case 5: ctx->entry.mnemonic = "FISUBR"; break;
                    case 6: ctx->entry.mnemonic = "FIDIV"; break;
                    case 7: ctx->entry.mnemonic = "FIDIVR"; break;
                }
            } else {
                if (reg == 3 && rm == 1) ctx->entry.mnemonic = "FCOMPP";
                else {
                    ctx->entry.op1 = OP_STi;
                    ctx->entry.op2 = OP_ST0;
                    switch (reg) {
                        case 0: ctx->entry.mnemonic = "FADDP"; break;
                        case 1: ctx->entry.mnemonic = "FMULP"; break;
                        case 4: ctx->entry.mnemonic = "FSUBRP"; break;
                        case 5: ctx->entry.mnemonic = "FSUBP"; break;
                        case 6: ctx->entry.mnemonic = "FDIVRP"; break;
                        case 7: ctx->entry.mnemonic = "FDIVP"; break;
                    }
                }
            }
            break;
        case 0xDF:
            if (mod != 3) {
                switch (reg) {
                    case 0: ctx->entry.mnemonic = "FILD"; ctx->entry.op1 = M_I16; break;
                    case 1: ctx->entry.mnemonic = "FISTTP"; ctx->entry.op1 = M_I16; break;
                    case 2: ctx->entry.mnemonic = "FIST"; ctx->entry.op1 = M_I16; break;
                    case 3: ctx->entry.mnemonic = "FISTP"; ctx->entry.op1 = M_I16; break;
                    case 4: ctx->entry.mnemonic = "FBLD"; ctx->entry.op1 = M_BCD; break;
                    case 5: ctx->entry.mnemonic = "FILD"; ctx->entry.op1 = M_I64; break;
                    case 6: ctx->entry.mnemonic = "FBSTP"; ctx->entry.op1 = M_BCD; break;
                    case 7: ctx->entry.mnemonic = "FISTP"; ctx->entry.op1 = M_I64; break;
                }
            } else {
                if (reg == 4 && rm == 0) { ctx->entry.mnemonic = "FNSTSW"; ctx->entry.op1 = OP_rAX; }
                else if (reg == 5) { ctx->entry.mnemonic = "FUCOMI"; ctx->entry.op1 = OP_ST0; ctx->entry.op2 = OP_STi; }
                else if (reg == 6) { ctx->entry.mnemonic = "FCOMI"; ctx->entry.op1 = OP_ST0; ctx->entry.op2 = OP_STi; }
            }
            break;
    }
}

int Disassemble(uint8_t* buffer, uint32_t eip, DecodeContext* out_ctx) {
    int instr_len = ParseInstuction(buffer, eip, out_ctx);
    FormatInstruction(buffer,out_ctx);
	return instr_len;
}


int ParseInstuction(uint8_t* buffer, uint32_t eip, DecodeContext* out_ctx) {
    memset(out_ctx, 0, sizeof(DecodeContext));
    out_ctx->buffer = buffer;
    out_ctx->max_len = MAX_INSTRUCTION_LENGTH;
    out_ctx->eip = eip;


    // 1. 解析前缀
    ParsePrefixes(out_ctx);

    // 2. 检查是否是双字节操作码
    // 0x0F 是转义字节，表示后面紧跟的是双字节操作码表中的指令
    if (out_ctx->pos < out_ctx->max_len && buffer[out_ctx->pos] == 0x0F) {
        out_ctx->is_two_byte_opcode = true;
        out_ctx->pos++;
    }

    // 3. 读取操作码
    out_ctx->opcode = ReadByte(out_ctx);

    // 4. 查找指令表项
    OpcodeEntry* entry;
    if (out_ctx->is_two_byte_opcode) {
        entry = (OpcodeEntry*)&two_byte_opcode_table[out_ctx->opcode];
    }
    else {
        entry = (OpcodeEntry*)&opcode_table[out_ctx->opcode];
    }

    if (entry->mnemonic == NULL && entry->group_table == NULL && !entry->is_prefix) {
        // 未知指令
        snprintf(out_ctx->asm_str, sizeof(out_ctx->asm_str), "??? [%02X]", out_ctx->opcode);

        // 打印已读取的所有字节
        int hex_pos = 0;
        for (int i = 0; i < out_ctx->pos && i < 15; i++) {
            hex_pos += snprintf(out_ctx->hex_str + hex_pos, sizeof(out_ctx->hex_str) - hex_pos, "%02X ", buffer[i]);
        }
        return out_ctx->pos;
    }

    out_ctx->entry = *entry;

    // 5. 解析 ModR/M
    // 如果指令定义中标记了 HAS_MODRM，则必须解析 ModR/M 字节
    // ModR/M 字节决定了操作数是寄存器还是内存，以及具体的寻址方式
    if (entry->has_modrm) {
        ParseModRM(out_ctx);
        out_ctx->has_modrm = true;

        // 检查是否需要 SIB
        // 32位模式下，当 R/M = 100 (ESP) 时，表示后面紧跟 SIB 字节
        if (out_ctx->mod != 3 && out_ctx->rm == 4 && (out_ctx->pfx_addr_size != 0x67)) {
            ParseSIB(out_ctx);
        }

        // 解析位移
        ParseDisplacement(out_ctx);
    }

    // 6. 处理分组指令
    // 某些 Opcode (如 0x80, 0x81, 0x83, 0xFF 等) 并不对应单一指令
    // 而是根据 ModR/M 中的 Reg 字段 (0-7) 来区分不同的指令 (如 ADD, OR, ADC...)
    // 这就是所谓的 "Group" 机制
    const char* mnemonic = entry->mnemonic;
    OperandType op1 = entry->op1;
    OperandType op2 = entry->op2;
    OperandType op3 = entry->op3;

    if (entry->group_table != NULL) {
        // 使用 ModR/M 的 Reg 字段作为索引查 Group 表
        GroupEntry* group = &entry->group_table[out_ctx->reg];
        if (group->mnemonic != NULL) {
            mnemonic = group->mnemonic;
            // Group 表的操作数可能覆盖主表
            // 例如 F6/F7 Group 3，Opcode 表里操作数是 NONE，完全由 Group 表定义
            if (group->operand[0] != NONE) op1 = group->operand[0];
            if (group->operand[1] != NONE) op2 = group->operand[1];
            if (group->operand[2] != NONE) op3 = group->operand[2];
        }
    }

    // 处理 FPU 指令 (0xD8 - 0xDF)
    if (out_ctx->opcode >= 0xD8 && out_ctx->opcode <= 0xDF) {
        ParseFPU(out_ctx);
        mnemonic = out_ctx->entry.mnemonic;
        op1 = out_ctx->entry.op1;
        op2 = out_ctx->entry.op2;
        op3 = out_ctx->entry.op3;
    }

    // 处理 0x66 前缀导致的助记符变化
    if (out_ctx->pfx_op_size == 0x66 && !out_ctx->is_two_byte_opcode) {
        switch (out_ctx->opcode) {
            case 0x60: mnemonic = "PUSHA"; break;
            case 0x61: mnemonic = "POPA"; break;
            case 0x98: mnemonic = "CBW"; break;
            case 0x99: mnemonic = "CWD"; break;
            case 0x9C: mnemonic = "PUSHF"; break;
            case 0x9D: mnemonic = "POPF"; break;
            case 0xA5: mnemonic = "MOVSW"; break;
            case 0xA7: mnemonic = "CMPSW"; break;
            case 0xAB: mnemonic = "STOSW"; break;
            case 0xAD: mnemonic = "LODSW"; break;
            case 0xAF: mnemonic = "SCASW"; break;
            case 0xCF: mnemonic = "IRET"; break;
        }
    }

    // 将解析出的最终 mnemonic 和 operand 更新回 context
    out_ctx->entry.mnemonic = mnemonic;
    out_ctx->entry.op1 = op1;
    out_ctx->entry.op2 = op2;
    out_ctx->entry.op3 = op3;

    // 7. 解析立即数
    int imm_parse_idx = 0; //根据传入的索引（0 或 1），决定将读取到的值写入 ctx->imm 还是 ctx->imm2。
    if (IsImmediate(op1)) ParseImmediate(out_ctx, op1, imm_parse_idx++);
    if (IsImmediate(op2)) ParseImmediate(out_ctx, op2, imm_parse_idx++);
    if (IsImmediate(op3)) ParseImmediate(out_ctx, op3, imm_parse_idx++);

    return out_ctx->pos;
}


void FormatInstruction(uint8_t* buffer,DecodeContext* out_ctx) {
	OperandType op1 = out_ctx->entry.op1;
    OperandType op2 = out_ctx->entry.op2;
    OperandType op3 = out_ctx->entry.op3;
	const char* mnemonic = out_ctx->entry.mnemonic;

    // 8. 生成汇编字符串
    char operand1[64] = "";
    char operand2[64] = "";
    char operand3[64] = "";

    int imm_fmt_idx = 0;
    if (op1 != NONE) FormatOperand(out_ctx, operand1, sizeof(operand1), op1, &imm_fmt_idx);
    if (op2 != NONE) FormatOperand(out_ctx, operand2, sizeof(operand2), op2, &imm_fmt_idx);
    if (op3 != NONE) FormatOperand(out_ctx, operand3, sizeof(operand3), op3, &imm_fmt_idx);

    // 组装最终字符串
    char prefix_str[32] = "";
    if (out_ctx->pfx_lock) strcat(prefix_str, "LOCK ");
    if (out_ctx->pfx_rep) strcat(prefix_str, "REP ");
    if (out_ctx->pfx_repne) strcat(prefix_str, "REPNE ");


    if (op3 != NONE) {
        snprintf(out_ctx->asm_str, sizeof(out_ctx->asm_str), "%s%s %s, %s, %s",
            prefix_str, mnemonic, operand1, operand2, operand3);
    }
    else if (op2 != NONE) {
        snprintf(out_ctx->asm_str, sizeof(out_ctx->asm_str), "%s%s %s, %s",
            prefix_str, mnemonic, operand1, operand2);
    }
    else if (op1 != NONE) {
        snprintf(out_ctx->asm_str, sizeof(out_ctx->asm_str), "%s%s %s",
            prefix_str, mnemonic, operand1);
    }
    else {
        snprintf(out_ctx->asm_str, sizeof(out_ctx->asm_str), "%s%s", prefix_str, mnemonic);
    }

    // 9. 生成机器码十六进制字符串
    int instr_len = out_ctx->pos;
    int hex_pos = 0;
    for (int i = 0; i < instr_len && i < 15; i++) {
        hex_pos += snprintf(out_ctx->hex_str + hex_pos, sizeof(out_ctx->hex_str) - hex_pos,
            "%02X ", buffer[i]);
    }

}