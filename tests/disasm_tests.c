#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../disasm.h"

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define TEST(name) static void name(void)

#define ASSERT_TRUE(expr) do { \
    g_tests_run++; \
    if (!(expr)) { \
        g_tests_failed++; \
        printf("[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return; \
    } \
} while (0)

#define ASSERT_EQ_INT(expected, actual) do { \
    g_tests_run++; \
    if ((expected) != (actual)) { \
        g_tests_failed++; \
        printf("[FAIL] %s:%d: expected %d got %d\n", __FILE__, __LINE__, (int)(expected), (int)(actual)); \
        return; \
    } \
} while (0)

#define ASSERT_EQ_U32(expected, actual) do { \
    g_tests_run++; \
    if ((uint32_t)(expected) != (uint32_t)(actual)) { \
        g_tests_failed++; \
        printf("[FAIL] %s:%d: expected 0x%08X got 0x%08X\n", __FILE__, __LINE__, (uint32_t)(expected), (uint32_t)(actual)); \
        return; \
    } \
} while (0)

#define ASSERT_STREQ(expected, actual) do { \
    g_tests_run++; \
    if (strcmp((expected), (actual)) != 0) { \
        g_tests_failed++; \
        printf("[FAIL] %s:%d: expected '%s' got '%s'\n", __FILE__, __LINE__, (expected), (actual)); \
        return; \
    } \
} while (0)

static void InitDecodeContext(DecodeContext* ctx, const uint8_t* bytes, int len, uint32_t eip) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->buffer = bytes;
    ctx->max_len = len;
    ctx->pos = 0;
    ctx->eip = eip;
}

TEST(Test_GetRegisterName) {
    ASSERT_STREQ("AL", GetRegisterName(8, 0));
    ASSERT_STREQ("AX", GetRegisterName(16, 0));
    ASSERT_STREQ("EAX", GetRegisterName(32, 0));
    ASSERT_STREQ("CS", GetRegisterName(1, 1));
}

TEST(Test_ParsePrefixes_basic) {
    uint8_t buf[] = { 0xF0, 0xF3, 0x66, 0x2E, 0x90 };
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0x1000);

    ParsePrefixes(&ctx);

    ASSERT_TRUE(ctx.pfx_lock);
    ASSERT_TRUE(ctx.pfx_rep);
    ASSERT_EQ_INT(0x66, ctx.pfx_op_size);
    ASSERT_EQ_INT(0x2E, ctx.pfx_segment);
    ASSERT_EQ_INT(4, ctx.pos);
}

TEST(Test_ParsePrefixes_stop_on_non_prefix) {
    uint8_t buf[] = { 0x66, 0x90, 0xF3 };
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0x1000);

    ParsePrefixes(&ctx);

    ASSERT_EQ_INT(1, ctx.pos);
    ASSERT_EQ_INT(0x66, ctx.pfx_op_size);
    ASSERT_TRUE(!ctx.pfx_rep);
}

TEST(Test_ParseModRM_extract_fields) {
    uint8_t buf[] = { 0xC1 }; // 11 000 001
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);

    ParseModRM(&ctx);

    ASSERT_EQ_INT(0xC1, ctx.modrm);
    ASSERT_EQ_INT(3, ctx.mod);
    ASSERT_EQ_INT(0, ctx.reg);
    ASSERT_EQ_INT(1, ctx.rm);
}

TEST(Test_ParseSIB_extract_fields) {
    uint8_t buf[] = { 0x64 }; // 01 100 100 : scale=1 index=4 base=4
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);

    ParseSIB(&ctx);

    ASSERT_TRUE(ctx.has_sib);
    ASSERT_EQ_INT(1, ctx.scale);
    ASSERT_EQ_INT(4, ctx.index);
    ASSERT_EQ_INT(4, ctx.base);
}

TEST(Test_ParseDisplacement_32_mod00_rm5_disp32) {
    uint8_t buf[] = { 0x78, 0x56, 0x34, 0x12 };
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);
    ctx.pfx_addr_size = 0;
    ctx.mod = 0;
    ctx.rm = 5;

    ParseDisplacement(&ctx);

    ASSERT_EQ_INT(4, ctx.disp_len);
    ASSERT_EQ_U32(0x12345678u, (uint32_t)ctx.disp);
    ASSERT_EQ_INT(4, ctx.pos);
}

TEST(Test_ParseDisplacement_32_mod01_disp8_sign) {
    uint8_t buf[] = { 0xF0 }; // -16
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);
    ctx.pfx_addr_size = 0;
    ctx.mod = 1;
    ctx.rm = 0;

    ParseDisplacement(&ctx);

    ASSERT_EQ_INT(1, ctx.disp_len);
    ASSERT_EQ_INT(-16, ctx.disp);
}

TEST(Test_ParseDisplacement_32_sib_base5_mod0) {
    uint8_t buf[] = { 0x78, 0x56, 0x34, 0x12 };
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);
    ctx.pfx_addr_size = 0;
    ctx.mod = 0;
    ctx.rm = 4;
    ctx.has_sib = true;
    ctx.base = 5;

    ParseDisplacement(&ctx);

    ASSERT_EQ_INT(4, ctx.disp_len);
    ASSERT_EQ_U32(0x12345678u, (uint32_t)ctx.disp);
}

TEST(Test_ParseDisplacement_16_mod00_rm6_disp16) {
    uint8_t buf[] = { 0x34, 0x12 };
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);
    ctx.pfx_addr_size = 0x67;
    ctx.mod = 0;
    ctx.rm = 6;

    ParseDisplacement(&ctx);

    ASSERT_EQ_INT(2, ctx.disp_len);
    ASSERT_EQ_INT(0x1234, (uint16_t)ctx.disp);
}

TEST(Test_ParseImmediate_Ib) {
    uint8_t buf[] = { 0x7F };
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);

    ParseImmediate(&ctx, Ib, 0);

    ASSERT_EQ_INT(1, ctx.imm_len);
    ASSERT_EQ_INT(0x7F, (int)ctx.imm);
}

TEST(Test_ParseImmediate_Iz_16bit_by_66_prefix) {
    uint8_t buf[] = { 0x34, 0x12 };
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);
    ctx.pfx_op_size = 0x66;

    ParseImmediate(&ctx, Iz, 0);

    ASSERT_EQ_INT(2, ctx.imm_len);
    ASSERT_EQ_INT(0x1234, (uint16_t)ctx.imm);
}

TEST(Test_ParseImmediate_Iz_32bit_default) {
    uint8_t buf[] = { 0x78, 0x56, 0x34, 0x12 };
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);

    ParseImmediate(&ctx, Iz, 0);

    ASSERT_EQ_INT(4, ctx.imm_len);
    ASSERT_EQ_U32(0x12345678u, (uint32_t)ctx.imm);
}

TEST(Test_ParseImmediate_Ap_16_16) {
    // offset=0x1234 segment=0xABCD -> imm = 0xABCD1234
    uint8_t buf[] = { 0x34, 0x12, 0xCD, 0xAB };
    DecodeContext ctx;
    InitDecodeContext(&ctx, buf, (int)sizeof(buf), 0);
    ctx.pfx_op_size = 0x66;

    ParseImmediate(&ctx, Ap, 0);

    ASSERT_EQ_INT(4, ctx.imm_len);
    ASSERT_EQ_U32(0xABCD1234u, (uint32_t)ctx.imm);
}

TEST(Test_FormatModRM_register_operand) {
    DecodeContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.mod = 3;
    ctx.rm = 0;

    char out[64];
    FormatModRM(&ctx, out, (int)sizeof(out), Ev);

    ASSERT_STREQ("EAX", out);
}

TEST(Test_FormatModRM_memory_default_DS) {
    // [EAX]
    DecodeContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.mod = 0;
    ctx.rm = 0;

    char out[64];
    FormatModRM(&ctx, out, (int)sizeof(out), Ev);

    ASSERT_STREQ("DWORD PTR DS:[EAX]", out);
}

TEST(Test_FormatModRM_memory_default_SS_for_EBP) {
    // [EBP+0x10]
    DecodeContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.mod = 1;
    ctx.rm = 5;
    ctx.disp = 0x10;
    ctx.disp_len = 1;

    char out[64];
    FormatModRM(&ctx, out, (int)sizeof(out), Ev);

    ASSERT_STREQ("DWORD PTR SS:[EBP+0x10]", out);
}

TEST(Test_FormatOperand_relative_jump) {
    // Jb: target = eip + pos + val
    DecodeContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eip = 0x1000;
    ctx.pos = 2;
    ctx.imm = 0x7E;

    char out[64];
    int idx = 0;
    FormatOperand(&ctx, out, (int)sizeof(out), Jb, &idx);

    ASSERT_STREQ("0x00001080", out);
}

TEST(Test_ParseInstruction_group1_80_add) {
    // 80 /0 ib : ADD r/m8, imm8
    // ADD BYTE PTR DS:[EAX], 0x7F
    uint8_t buf[] = { 0x80, 0x00, 0x7F };
    DecodeContext ctx;
    int len = ParseInstuction(buf, 0x1000, &ctx);

    ASSERT_EQ_INT(3, len);
    ASSERT_STREQ("ADD", ctx.entry.mnemonic);
    ASSERT_EQ_INT(Eb, ctx.entry.op1);
    ASSERT_EQ_INT(Ib, ctx.entry.op2);

    FormatInstruction(buf, &ctx);
    ASSERT_STREQ("ADD BYTE PTR DS:[EAX], 0x7F", ctx.asm_str);
}

TEST(Test_ParseInstruction_group3_F6_not) {
    // F6 /2 : NOT r/m8
    // NOT BYTE PTR DS:[EAX]
    uint8_t buf[] = { 0xF6, 0x10 }; // mod=00 reg=2 rm=0
    DecodeContext ctx;
    int len = ParseInstuction(buf, 0x2000, &ctx);

    ASSERT_EQ_INT(2, len);
    ASSERT_STREQ("NOT", ctx.entry.mnemonic);
    ASSERT_EQ_INT(Eb, ctx.entry.op1);
    ASSERT_EQ_INT(NONE, ctx.entry.op2);

    FormatInstruction(buf, &ctx);
    ASSERT_STREQ("NOT BYTE PTR DS:[EAX]", ctx.asm_str);
}

TEST(Test_ParseInstruction_two_byte_setz) {
    // 0F 94 /r : SETZ Eb
    uint8_t buf[] = { 0x0F, 0x94, 0xC0 }; // mod=11 reg=0 rm=0 => AL
    DecodeContext ctx;
    int len = ParseInstuction(buf, 0x3000, &ctx);

    ASSERT_EQ_INT(3, len);
    ASSERT_TRUE(ctx.is_two_byte_opcode);
    ASSERT_STREQ("SETZ", ctx.entry.mnemonic);

    FormatInstruction(buf, &ctx);
    ASSERT_STREQ("SETZ AL", ctx.asm_str);
}

TEST(Test_Disassemble_end_to_end) {
    uint8_t buf[] = { 0x66, 0x60 }; // PUSHA
    DecodeContext ctx;
    int len = Disassemble(buf, 0x4000, &ctx);

    ASSERT_EQ_INT(2, len);
    ASSERT_STREQ("PUSHA", ctx.entry.mnemonic);
    ASSERT_STREQ("PUSHA", ctx.asm_str);
}

static void RunAllTests(void) {
    Test_GetRegisterName();
    Test_ParsePrefixes_basic();
    Test_ParsePrefixes_stop_on_non_prefix();
    Test_ParseModRM_extract_fields();
    Test_ParseSIB_extract_fields();
    Test_ParseDisplacement_32_mod00_rm5_disp32();
    Test_ParseDisplacement_32_mod01_disp8_sign();
    Test_ParseDisplacement_32_sib_base5_mod0();
    Test_ParseDisplacement_16_mod00_rm6_disp16();
    Test_ParseImmediate_Ib();
    Test_ParseImmediate_Iz_16bit_by_66_prefix();
    Test_ParseImmediate_Iz_32bit_default();
    Test_ParseImmediate_Ap_16_16();
    Test_FormatModRM_register_operand();
    Test_FormatModRM_memory_default_DS();
    Test_FormatModRM_memory_default_SS_for_EBP();
    Test_FormatOperand_relative_jump();
    Test_ParseInstruction_group1_80_add();
    Test_ParseInstruction_group3_F6_not();
    Test_ParseInstruction_two_byte_setz();
    Test_Disassemble_end_to_end();
}

int main(void) {
    RunAllTests();

    if (g_tests_failed) {
        printf("%d/%d assertions failed\n", g_tests_failed, g_tests_run);
        return 1;
    }

    printf("All tests passed (%d assertions)\n", g_tests_run);
    return 0;
}
