/* Instruction description tables */

/* Generic instruction types */
#define INST_TYPE_UNKNOWN		0 /* Unknown/not implemented */
#define INST_TYPE_INVALID		1 /* Invalid instruction */
#define INST_TYPE_PRIVILEGED	2 /* Privileged instruction */
#define INST_TYPE_UNSUPPORTED	3 /* Unsupported instruction */
#define INST_TYPE_EXTENSION		4 /* Opcode extension, use ModR/M R field to distinguish */
#define INST_TYPE_NORMAL		5 /* Normal instruction which does not need special handling */

/* Special instruction types */
#define INST_TYPE_SPECIAL		6
#define INST_MOV_MOFFSET		(INST_TYPE_SPECIAL + 0)
#define INST_CALL_DIRECT		(INST_TYPE_SPECIAL + 1)
#define INST_CALL_INDIRECT		(INST_TYPE_SPECIAL + 2)
#define INST_RET				(INST_TYPE_SPECIAL + 3)
#define INST_RETN				(INST_TYPE_SPECIAL + 4)
#define INST_JMP_DIRECT			(INST_TYPE_SPECIAL + 5)
#define INST_JMP_INDIRECT		(INST_TYPE_SPECIAL + 6)
/* Jcc occupies 16 instruction types for each condition code */
#define INST_JCC				(INST_TYPE_SPECIAL + 7)
#define GET_JCC_COND(type)		((type) - INST_JCC)
#define INST_JCC_REL8			(INST_TYPE_SPECIAL + 23)
#define INST_INT				(INST_TYPE_SPECIAL + 24)
#define INST_MOV_FROM_SEG		(INST_TYPE_SPECIAL + 25)
#define INST_MOV_TO_SEG			(INST_TYPE_SPECIAL + 26)

#define REG_AX			0x00000001 /* AL, AH, AX, EAX, RAX register */
#define REG_CX			0x00000002 /* CL, CH, CX, ECX, RCX register */
#define REG_DX			0x00000004 /* DL, DH, DX, EDX, RDX register */
#define REG_BX			0x00000008 /* BL, BH, BX, EBX, RBX register */
#define REG_SP			0x00000010 /* SPL, SP, ESP, RSP register */
#define REG_BP			0x00000020 /* BPL, BP, EBP, RBP register */
#define REG_SI			0x00000040 /* SIL, SI, ESI, RSI register */
#define REG_DI			0x00000080 /* DIL, DI, EDI, RDI register */
#define REG_R8			0x00000100 /* R8L, R8W, R8D, R8 register */
#define REG_R9			0x00000200 /* R9L, R9W, R9D, R9 register */
#define REG_R10			0x00000400 /* R10L, R10W, R10D, R10 register */
#define REG_R11			0x00000800 /* R11L, R11W, R11D, R11 register */
#define REG_R12			0x00001000 /* R12L, R12W, R12D, R12 register */
#define REG_R13			0x00002000 /* R13L, R13W, R13D, R13 register */
#define REG_R14			0x00004000 /* R14L, R14W, R14D, R14 register */
#define REG_R15			0x00008000 /* R15L, R15W, R15D, R15 register */
#define REG_MASK(r)		(1 << (r)) /* Generate a mask from a numeric register id */
#define MODRM_R			0x01000000 /* R field of ModR/M */
#define MODRM_RM_R		0x02000000 /* Register type of ModR/M R/M field */
#define MODRM_RM_M		0x04000000 /* Memory type of ModR/M R/M field */
#define MODRM_RM		MODRM_RM_R | MODRM_RM_M /* R/M field of ModR/M */

#define PREFIX_OPERAND_SIZE		-1 /* Indicate imm_bytes is 2 or 4 bytes depends on operand size prefix */
#ifdef _WIN64
#define PREFIX_OPERAND_SIZE_64	-2 /* Indicate imm_bytes is 2 or 4 or 8 bytes depends on operand size prefix */
#else
#define PREFIX_OPERAND_SIZE_64	PREFIX_OPERAND_SIZE /* Not supported on x86 */
#endif
#define PREFIX_ADDRESS_SIZE		-3 /* Indicate imm_bytes is 2 or 4 or 8 bytes depends on address size prefix */
#define PREFIX_ADDRESS_SIZE_64	PREFIX_ADDRESS_SIZE /* Indicate imm_bytes is 2 or 4 or 8 bytes depends on address size prefix */
struct instruction_desc
{
	int type; /* Instruction type */
	int has_modrm; /* Whether the instruction has ModR/M opcode */
	int imm_bytes; /* Bytes of immediate, or PREFIX_OPERAND_SIZE(_64) */
	int read_regs; /* The bitmask of registers which are read from */
	int write_regs; /* The bitmask of registers which are written to */
	struct instruction_desc *extension_table; /* Secondary lookup table for INST_TYPE_EXTENSION */
};
#define UNKNOWN()		{ .type = INST_TYPE_UNKNOWN },
#define INVALID()		{ .type = INST_TYPE_INVALID },
#define PRIVILEGED()	{ .type = INST_TYPE_PRIVILEGED },
#define UNSUPPORTED()	{ .type = INST_TYPE_UNSUPPORTED },
#define EXTENSION(x)	{ .type = INST_TYPE_EXTENSION, .has_modrm = 1, .extension_table = &extension_##x },

#define INST_UNTESTED(...)		UNSUPPORTED() /* FIXME: Temporary for now */
#define INST(...)		{ .type = INST_TYPE_NORMAL, __VA_ARGS__ },
#define SPECIAL(s, ...)	{ .type = s, __VA_ARGS__ },
#define MODRM()			.has_modrm = 1
#define IMM(i)			.imm_bytes = (i)
#define READ(x)			.read_regs = (x)
#define WRITE(x)		.write_regs = (x)

static const struct instruction_desc extension_C6[8] =
{ 
	/* 0: MOV r/m8, imm8 */ INST(MODRM(), IMM(1), WRITE(MODRM_RM))
	/* 1: ??? */ UNKNOWN()
	/* 2: ??? */ UNKNOWN()
	/* 3: ??? */ UNKNOWN()
	/* 4: ??? */ UNKNOWN()
	/* 5: ??? */ UNKNOWN()
	/* 6: ??? */ UNKNOWN()
	/* 7: ??? */ UNKNOWN()
};

static const struct instruction_desc extension_C7[8] =
{
	/* 0: MOV r/m?, imm? */ INST(MODRM(), IMM(PREFIX_OPERAND_SIZE), WRITE(MODRM_RM))
	/* 1: ??? */ UNKNOWN()
	/* 2: ??? */ UNKNOWN()
	/* 3: ??? */ UNKNOWN()
	/* 4: ??? */ UNKNOWN()
	/* 5: ??? */ UNKNOWN()
	/* 6: ??? */ UNKNOWN()
	/* 7: ??? */ UNKNOWN()
};

/* [GRP3]: 0/TEST, 2/NOT, 3/NEG, 4/MUL, 5/IMUL, 6/DIV, 7/IDIV */
static const struct instruction_desc extension_F6[8] =
{
	/* 0: TEST r/m8, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM))
	/* 1: ??? */ UNKNOWN()
	/* 2: NOT r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 3: NEG r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 4: MUL r/m8 */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX))
	/* 5: IMUL r/m8 */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX))
	/* 6: DIV r/m8 */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX))
	/* 7: IDIV r/m8 */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX))
};

static const struct instruction_desc extension_F7[8] =
{
	/* 0: TEST r/m?, imm? */ INST(MODRM(), IMM(PREFIX_OPERAND_SIZE), READ(MODRM_RM))
	/* 1: ??? */ UNKNOWN()
	/* 2: NOT r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 3: NEG r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 4: MUL r/m? */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX | REG_DX))
	/* 5: IMUL r/m? */ INST(MODRM(), READ(REG_AX | MODRM_RM), WRITE(REG_AX | REG_DX))
	/* 6: DIV r/m? */ INST(MODRM(), READ(REG_AX | REG_DX | MODRM_RM), WRITE(REG_AX | REG_DX))
	/* 7: IDIV r/m? */ INST(MODRM(), READ(REG_AX | REG_DX | MODRM_RM), WRITE(REG_AX | REG_DX))
};

static const struct instruction_desc extension_FF[8] = 
{
	/* 0: INC r/m16; INC r/m32 */ INST(MODRM(), READ(MODRM_RM_R), WRITE(MODRM_RM_R))
	/* 1: DEC r/m16; DEC r/m32 */ INST(MODRM(), READ(MODRM_RM_R), WRITE(MODRM_RM_R))
	/* 2: CALL r/m16; CALL r/m32 */ SPECIAL(INST_CALL_INDIRECT, MODRM())
	/* 3: CALL FAR m16:16; CALL FAR m16:32 */ UNSUPPORTED()
	/* 4: JMP r/m32; JMP r/m64 */ SPECIAL(INST_JMP_INDIRECT, MODRM())
	/* 5: JMP FAR m16:16; JMP FAR m16:32 */ UNSUPPORTED()
	/* 6: PUSH r/m16; PUSH r/m32 */ INST(MODRM(), READ(MODRM_RM_R))
	/* 7: ??? */ UNKNOWN()
};

static const struct instruction_desc one_byte_inst[256] =
{
	/* 0x00: ADD r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x01: ADD r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x02: ADD r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x03: ADD r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x04: ADD AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x05: ADD ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x06: ??? */ UNKNOWN()
#ifdef _WIN64
	/* 0x07: INVALID */ INVALID()
#else
	/* 0x07: POP ES */ UNSUPPORTED()
#endif
	/* 0x08: OR r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x09: OR r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x0A: OR r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0B: OR r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0C: OR AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x0D: OR ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x0E: ??? */ UNKNOWN()
	/* 0x0F: ??? */ UNKNOWN()
	/* 0x10: ADC r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x11: ADC r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x12: ADC r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x13: ADC r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x14: ADC AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x15: ADC ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x16: ??? */ UNKNOWN()
#ifdef _WIN64
	/* 0x17: INVALID */ INVALID()
#else
	/* 0x17: POP SS */ UNSUPPORTED()
#endif
	/* 0x18: SBB r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x19: SBB r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x1A: SBB r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x1B: SBB r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x1C: SBB AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x1D: SBB ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x1E: ??? */ UNKNOWN()
#ifdef _WIN64
	/* 0x1F: INVALID */ INVALID()
#else
	/* 0x1F: POP DS */ UNSUPPORTED()
#endif
	/* 0x20: AND r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x21: AND r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x22: AND r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x23: AND r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x24: AND AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x25: AND ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x26: ES segment prefix */ INVALID()
#ifdef _WIN64
	/* 0x27: INVALID */ INVALID()
#else
	/* 0x27: DAA */ INST_UNTESTED(READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0x28: SUB r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x29: SUB r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x2A: SUB r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x2B: SUB r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x2C: SUB AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x2D: SUB ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x2E: CS segment prefix */ INVALID()
#ifdef _WIN64
	/* 0x2F: INVALID */ INVALID()
#else
	/* 0x2F: DAS */ INST_UNTESTED(READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0x30: XOR r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x31: XOR r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x32: XOR r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x33: XOR r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x34: XOR AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x35: XOR ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x36: SS segment prefix */ INVALID()
#ifdef _WIN64
	/* 0x37: Invalid */ INVALID()
#else
	/* 0x37: AAA */ INST_UNTESTED(READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0x38: CMP r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x39: CMP r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x3A: CMP r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3B: CMP r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3C: CMP AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x3D: CMP ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x3E: DS segment prefix */ INVALID()
#ifdef _WIN64
	/* 0x3F; INVALID */ INVALID()
	/* 0x40: REX prefix */ INVALID()
	/* 0x41: REX prefix */ INVALID()
	/* 0x42: REX prefix */ INVALID()
	/* 0x43: REX prefix */ INVALID()
	/* 0x44: REX prefix */ INVALID()
	/* 0x45: REX prefix */ INVALID()
	/* 0x46: REX prefix */ INVALID()
	/* 0x47: REX prefix */ INVALID()
	/* 0x48: REX prefix */ INVALID()
	/* 0x49: REX prefix */ INVALID()
	/* 0x4A: REX prefix */ INVALID()
	/* 0x4B: REX prefix */ INVALID()
	/* 0x4C: REX prefix */ INVALID()
	/* 0x4D: REX prefix */ INVALID()
	/* 0x4E: REX prefix */ INVALID()
	/* 0x4F: REX prefix */ INVALID()
#else
	/* 0x3F: AAS */ INST_UNTESTED(READ(REG_AX), WRITE(REG_AX))
	/* 0x40: INC ?AX */ INST(READ(REG_AX), WRITE(REG_AX))
	/* 0x41: INC ?CX */ INST(READ(REG_CX), WRITE(REG_CX))
	/* 0x42: INC ?DX */ INST(READ(REG_DX), WRITE(REG_DX))
	/* 0x43: INC ?BX */ INST(READ(REG_BX), WRITE(REG_BX))
	/* 0x44: INC ?SP */ INST(READ(REG_SP), WRITE(REG_SP))
	/* 0x45: INC ?BP */ INST(READ(REG_BP), WRITE(REG_BP))
	/* 0x46: INC ?SI */ INST(READ(REG_SI), WRITE(REG_SI))
	/* 0x47: INC ?DI */ INST(READ(REG_DI), WRITE(REG_DI))
	/* 0x48: DEC ?AX */ INST(READ(REG_AX), WRITE(REG_AX))
	/* 0x49: DEC ?CX */ INST(READ(REG_CX), WRITE(REG_CX))
	/* 0x4A: DEC ?DX */ INST(READ(REG_DX), WRITE(REG_DX))
	/* 0x4B: DEC ?BX */ INST(READ(REG_BX), WRITE(REG_BX))
	/* 0x4C: DEC ?SP */ INST(READ(REG_SP), WRITE(REG_SP))
	/* 0x4D: DEC ?BP */ INST(READ(REG_BP), WRITE(REG_BP))
	/* 0x4E: DEC ?SI */ INST(READ(REG_SI), WRITE(REG_SI))
	/* 0x4F: DEC ?DI */ INST(READ(REG_DI), WRITE(REG_DI))
#endif
	/* NOTE: The read and write information of these are not very accurate */
	/* 0x50: PUSH ?AX/R8? */ INST(READ(REG_SP | REG_AX | REG_R8), WRITE(REG_SP))
	/* 0x51: PUSH ?CX/R9? */ INST(READ(REG_SP | REG_CX | REG_R9), WRITE(REG_SP))
	/* 0x52: PUSH ?DX/R10? */ INST(READ(REG_SP | REG_DX | REG_R10), WRITE(REG_SP))
	/* 0x53: PUSH ?BX/R11? */ INST(READ(REG_SP | REG_BX | REG_R11), WRITE(REG_SP))
	/* 0x54: PUSH ?SP/R12? */ INST(READ(REG_SP | REG_SP | REG_R12), WRITE(REG_SP))
	/* 0x55: PUSH ?BP/R13? */ INST(READ(REG_SP | REG_BP | REG_R13), WRITE(REG_SP))
	/* 0x56: PUSH ?SI/R14? */ INST(READ(REG_SP | REG_SI | REG_R14), WRITE(REG_SP))
	/* 0x57: PUSH ?DI/R15? */ INST(READ(REG_SP | REG_DI | REG_R15), WRITE(REG_SP))
	/* 0x58: POP ?AX/R8? */ INST(READ(REG_SP), WRITE(REG_SP | REG_AX | REG_R8))
	/* 0x59: POP ?CX/R9? */ INST(READ(REG_SP), WRITE(REG_SP | REG_CX | REG_R9))
	/* 0x5A: POP ?DX/R10? */ INST(READ(REG_SP), WRITE(REG_SP | REG_DX | REG_R10))
	/* 0x5B: POP ?BX/R11? */ INST(READ(REG_SP), WRITE(REG_SP | REG_BX | REG_R11))
	/* 0x5C: POP ?SP/R12? */ INST(READ(REG_SP), WRITE(REG_SP | REG_SP | REG_R12))
	/* 0x5D: POP ?BP/R13? */ INST(READ(REG_SP), WRITE(REG_SP | REG_BP | REG_R13))
	/* 0x5E: POP ?SI/R14? */ INST(READ(REG_SP), WRITE(REG_SP | REG_SI | REG_R14))
	/* 0x5F: POP ?DI/R15? */ INST(READ(REG_SP), WRITE(REG_SP | REG_DI | REG_R15))
#ifdef _WIN64
	/* 0x60: INVALID */ INVALID()
	/* 0x61: INVALID */ INVALID()
	/* 0x62: EVEX prefix */ INVALID()
	/* 0x63: INVALID */ INVALID()
#else
	/* 0x60: PUSHA_PUSHAD */ INST(READ(REG_AX | REG_CX | REG_DX | REG_BX | REG_SP | REG_BP | REG_SI | REG_DI), WRITE(REG_SP))
	/* 0x61: POPA/POPAD */ INST(READ(REG_SP), WRITE(REG_AX | REG_CX | REG_DX | REG_BX | REG_SP | REG_BP | REG_SI | REG_DI))
	/* 0x62: BOUND r?, m?&? */ INST_UNTESTED(MODRM(), READ(MODRM_R | MODRM_RM_M))
	/* 0x63: ARPL r/m16, r16 */ INST_UNTESTED(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
#endif
	/* 0x64: FS segment prefix */ INVALID()
	/* 0x65: GS segment prefix */ INVALID()
	/* 0x66: ??? */ UNKNOWN()
	/* 0x67: ??? */ UNKNOWN()
	/* 0x68: PUSH imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_SP), WRITE(REG_SP))
	/* 0x69: IMUL r?, r/m?, imm? */ INST(MODRM(), IMM(PREFIX_OPERAND_SIZE), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x6A: PUSH imm8 */ INST(IMM(1), READ(REG_SP), WRITE(REG_SP))
	/* 0x6B: IMUL r?, r/m?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x6C: INSB */ UNSUPPORTED()
	/* 0x6D: INSW/INSD */ UNSUPPORTED()
	/* 0x6E: OUTSB */ UNSUPPORTED()
	/* 0x6F: OUTSW/OUTSD */ UNSUPPORTED()
	/* 0x70: JO rel8 */ SPECIAL(INST_JCC + 0, IMM(1))
	/* 0x71: JNO rel8 */ SPECIAL(INST_JCC + 1, IMM(1))
	/* 0x72: JB/JC/JNAE rel8 */ SPECIAL(INST_JCC + 2, IMM(1))
	/* 0x73: JAE/JNB/JNC rel8 */ SPECIAL(INST_JCC + 3, IMM(1))
	/* 0x74: JE/JZ rel8 */ SPECIAL(INST_JCC + 4, IMM(1))
	/* 0x75: JNE/JNZ rel8 */ SPECIAL(INST_JCC + 5, IMM(1))
	/* 0x76: JBE/JNA rel8 */ SPECIAL(INST_JCC + 6, IMM(1))
	/* 0x77: JA/JNBE rel8 */ SPECIAL(INST_JCC + 7, IMM(1))
	/* 0x78: JS rel8 */ SPECIAL(INST_JCC + 8, IMM(1))
	/* 0x79: JNS rel8 */ SPECIAL(INST_JCC + 9, IMM(1))
	/* 0x7A: JP/JPE rel8 */ SPECIAL(INST_JCC + 10, IMM(1))
	/* 0x7B: JNP/JPO rel8 */ SPECIAL(INST_JCC + 11, IMM(1))
	/* 0x7C: JL/JNGE rel8 */ SPECIAL(INST_JCC + 12, IMM(1))
	/* 0x7D: JGE/JNL rel8 */ SPECIAL(INST_JCC + 13, IMM(1))
	/* 0x7E: JLE/JNG rel8 */ SPECIAL(INST_JCC + 14, IMM(1))
	/* 0x7F: JG/JNLE rel8 */ SPECIAL(INST_JCC + 15, IMM(1))
	/* [GRP1]: 0/ADD, 1/OR, 2/ADC, 3/SBB, 4/AND, 5/SUB, 6/XOR, 7/CMP */
	/* 0x80: [GRP1] r/m8, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x81: [GRP1] r/m?, imm? */ INST(MODRM(), IMM(PREFIX_OPERAND_SIZE), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x82: ??? */ UNKNOWN()
	/* 0x83: [GRP1] r/m?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x84: TEST r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0x85: TEST r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0x86: XCHG r8, r/m8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0x87: XCHG r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0x88: MOV r/m8, r8 */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* 0x89: MOV r/m?, r? */ INST(MODRM(), READ(MODRM_R), WRITE(MODRM_RM))
	/* 0x8A: MOV r8, r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x8B: MOV r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x8C: MOV r/m16, Sreg; MOV r/m64, Sreg */ SPECIAL(INST_MOV_FROM_SEG, MODRM(), WRITE(MODRM_RM))
	/* 0x8D: LEA r?, m */ INST(MODRM(), READ(MODRM_RM_M), WRITE(MODRM_R))
	/* 0x8E: MOV Sreg, r/m16; MOV Sreg, r/m64 */ SPECIAL(INST_MOV_TO_SEG, MODRM(), READ(MODRM_RM))
	/* 0x8F: POP r/m? */ INST(MODRM(), READ(REG_SP), WRITE(REG_SP | MODRM_RM))
	/* NOTE: The read and write information of these are not very accurate */
	/* 0x90: XCHG ?AX, ?AX/R8?; NOP */ INST()
	/* 0x91: XCHG ?AX, ?CX/R9? */ INST(READ(REG_AX | REG_CX | REG_R9), WRITE(REG_AX | REG_CX | REG_R9))
	/* 0x92: XCHG ?AX, ?DX/R10? */ INST(READ(REG_AX | REG_DX | REG_R10), WRITE(REG_AX | REG_DX | REG_R10))
	/* 0x93: XCHG ?AX, ?BX/R11? */ INST(READ(REG_AX | REG_BX | REG_R11), WRITE(REG_AX | REG_BX | REG_R11))
	/* 0x94: XCHG ?AX, ?SP/R12? */ INST(READ(REG_AX | REG_SP | REG_R12), WRITE(REG_AX | REG_SP | REG_R12))
	/* 0x95: XCHG ?AX, ?BP/R13? */ INST(READ(REG_AX | REG_BP | REG_R13), WRITE(REG_AX | REG_BP | REG_R13))
	/* 0x96: XCHG ?AX, ?SI/R14? */ INST(READ(REG_AX | REG_SI | REG_R14), WRITE(REG_AX | REG_SI | REG_R14))
	/* 0x97: XCHG ?AX, ?DI/R15? */ INST(READ(REG_AX | REG_DI | REG_R15), WRITE(REG_AX | REG_DI | REG_R15))
	/* 0x98: CBW; CWDE; CDQE */ INST_UNTESTED(READ(REG_AX), WRITE(REG_AX))
	/* 0x99: CWD; CDQ; CQO */ INST_UNTESTED(READ(REG_AX), WRITE(REG_AX | REG_DX))
#ifdef _WIN64
	/* 0x9A: INVALID */ INVALID()
#else
	/* 0x9A: CALL FAR ptr16:? */ UNSUPPORTED()
#endif
	/* 0x9B: FWAIT */ INST_UNTESTED()
	/* 0x9C: PUSHF/PUSHFD/PUSHFQ */ INST(READ(REG_SP), WRITE(REG_SP))
	/* 0x9D: POPF/POPFD/POPFQ */ INST(READ(REG_SP), WRITE(REG_SP))
#ifdef _WIN64
	/* 0x9E: INVALID */ INVALID()
	/* 0x9F: INVALID */ INVALID()
#else
	/* 0x9E: SAHF */ INST_UNTESTED(READ(REG_AX))
	/* 0x9F: LAHF */ INST_UNTESTED(WRITE(REG_AX))
#endif
	/* 0xA0: MOV AL, moffs8 */ SPECIAL(INST_MOV_MOFFSET, IMM(1))
	/* 0xA1: MOV ?AX, moffs? */ SPECIAL(INST_MOV_MOFFSET, IMM(PREFIX_ADDRESS_SIZE_64))
	/* 0xA2: MOV moffs8, AL */ SPECIAL(INST_MOV_MOFFSET, IMM(1))
	/* 0xA3: MOV moffs?, ?AX */ SPECIAL(INST_MOV_MOFFSET, IMM(PREFIX_ADDRESS_SIZE_64))
	/* 0xA4: MOVSB */ INST(READ(REG_SI | REG_DI))
	/* 0xA5: MOVSW/MOVSD/MOVSQ */ INST(READ(REG_SI | REG_DI))
	/* 0xA6: CMPSB */ INST(READ(REG_SI | REG_DI))
	/* 0xA7: CMPSW/CMPSD/CMPSDQ */ INST(READ(REG_SI | REG_DI))
	/* 0xA8: TEST AL, imm8 */ INST(IMM(1), READ(REG_AX))
	/* 0xA9: TEST ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX))
	/* 0xAA: STOSB */ INST(READ(REG_AX | REG_DI))
	/* 0xAB: STOSW/STOSD/STOSQ */ INST(READ(REG_AX | REG_DI))
	/* 0xAC: LODSB */ UNSUPPORTED()
	/* 0xAD: LODSW/LODSD/LODSQ */ UNSUPPORTED()
	/* 0xAE: SCASB */ UNSUPPORTED()
	/* 0xAF: SCASW/SCASD/SCASQ */ UNSUPPORTED()
	/* NOTE: The read and write information of these are not very accurate */
	/* 0xB0: MOV AL/R8L, imm8 */ INST(IMM(1), WRITE(REG_AX | REG_R8))
	/* 0xB1: MOV CL/R9L, imm8 */ INST(IMM(1), WRITE(REG_CX | REG_R9))
	/* 0xB2: MOV DL/R10L, imm8 */ INST(IMM(1), WRITE(REG_DX | REG_R10))
	/* 0xB3: MOV BL/R11L, imm8 */ INST(IMM(1), WRITE(REG_BX | REG_R11))
	/* 0xB4: MOV AH/SP/R12L, imm8 */ INST(IMM(1), WRITE(REG_AX | REG_SP | REG_R12))
	/* 0xB5: MOV CH/BP/R13L, imm8 */ INST(IMM(1), WRITE(REG_CX | REG_BP | REG_R13))
	/* 0xB6: MOV DH/SI/R14L, imm8 */ INST(IMM(1), WRITE(REG_DX | REG_SI | REG_R14))
	/* 0xB7: MOV BH/DI/R15L, imm8 */ INST(IMM(1), WRITE(REG_BX | REG_DI | REG_R15))
	/* 0xB8: MOV ?AX/R8?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_AX | REG_R8))
	/* 0xB9: MOV ?CX/R9?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_CX | REG_R9))
	/* 0xBA: MOV ?DX/R10?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_DX | REG_R10))
	/* 0xBB: MOV ?BX/R11?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_BX | REG_R11))
	/* 0xBC: MOV ?SP/R12?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_SP | REG_R12))
	/* 0xBD: MOV ?BP/R13?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_BP | REG_R13))
	/* 0xBE: MOV ?SI/R14?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_SI | REG_R14))
	/* 0xBF: MOV ?DI/R15?, imm? */ INST(IMM(PREFIX_OPERAND_SIZE_64), WRITE(REG_DI | REG_R15))
	/* [GRP2]: 0/ROL, 1/ROR, 2/RCL, 3/RCR, 4/SHL/SAL, 5/SHR, 7/SAR */
	/* 0xC0: [GRP2] r/m8, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xC1: [GRP2] r/m?, imm8 */ INST(MODRM(), IMM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xC2: RET imm16 */ SPECIAL(INST_RETN, IMM(2))
	/* 0xC3: RET */ SPECIAL(INST_RET)
#ifdef _WIN64
	/* 0xC4: INVALID */ INVALID()
	/* 0xC5: INVALID */ INVALID()
#else
	/* 0xC4: LES r?, m16:? */ UNSUPPORTED()
	/* 0xC5: LDS r?, m16:? */ UNSUPPORTED()
#endif
	/* 0xC6: */ EXTENSION(C6)
	/* 0xC7: */ EXTENSION(C7)
	/* 0xC8: ENTER */ UNSUPPORTED()
	/* 0xC9: LEAVE */ INST(READ(REG_BP), WRITE(REG_BP | REG_SP))
	/* 0xCA: RET FAR imm16 */ INST_UNTESTED(IMM(2))
	/* 0xCB: RET FAR */ INST_UNTESTED()
	/* 0xCC: INT 3 */ INST_UNTESTED()
	/* 0xCD: INT */ SPECIAL(INST_INT, IMM(1))
#ifdef _WIN64
	/* 0xCE: INVALID */ INVALID()
#else
	/* 0xCE: INTO */ INST_UNTESTED()
#endif
	/* 0xCF: IRET/IRETD/IRETQ */ INST_UNTESTED()
	/* 0xD0: [GRP2] r/m8, 1 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xD1: [GRP2] r/m?, 1 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xD2: [GRP2] r/m8, CL */ INST(MODRM(), READ(MODRM_RM | REG_CX), WRITE(MODRM_RM))
	/* 0xD3: [GRP2] r/m?, CL */ INST(MODRM(), READ(MODRM_RM | REG_CX), WRITE(MODRM_RM))
#ifdef _WIN64
	/* 0xD4: INVALID */ INVALID()
	/* 0xD5: INVALID */ INVALID()
#else
	/* 0xD4: AAM */ INST_UNTESTED(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0xD5: AAD */ INST_UNTESTED(IMM(1), READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0xD6: ??? */ UNKNOWN()
	/* 0xD7: XLAT */ UNSUPPORTED()
	/* 0xD8: (x87 escape) */ UNKNOWN()
	/* 0xD9: (x87 escape) */ UNKNOWN()
	/* 0xDA: (x87 escape) */ UNKNOWN()
	/* 0xDB: (x87 escape) */ UNKNOWN()
	/* 0xDC: (x87 escape) */ UNKNOWN()
	/* 0xDD: (x87 escape) */ UNKNOWN()
	/* 0xDE: (x87 escape) */ UNKNOWN()
	/* 0xDF: (x87 escape) */ UNKNOWN()
	/* 0xE0: LOOPNE rel8 */ SPECIAL(INST_JCC_REL8, IMM(1), READ(REG_CX), WRITE(REG_CX))
	/* 0xE1: LOOPE rel8 */ SPECIAL(INST_JCC_REL8, IMM(1), READ(REG_CX), WRITE(REG_CX))
	/* 0xE2: LOOP rel8 */ SPECIAL(INST_JCC_REL8, IMM(1), READ(REG_CX), WRITE(REG_CX))
	/* 0xE3: JCXZ/JECXZ rel8 */ SPECIAL(INST_JCC_REL8, IMM(1), READ(REG_CX))
	/* 0xE4: IN AL, imm8 */ INST_UNTESTED(IMM(1), WRITE(REG_AX))
	/* 0xE5: IN AX/EAX, imm8 */ INST_UNTESTED(IMM(1), WRITE(REG_AX))
	/* 0xE6: OUT imm8, AL */ INST_UNTESTED(IMM(1), READ(REG_AX))
	/* 0xE7: OUT imm8, AX/EAX */ INST_UNTESTED(IMM(1), READ(REG_AX))
	/* 0xE8: CALL rel16/rel32 */ SPECIAL(INST_CALL_DIRECT, IMM(PREFIX_OPERAND_SIZE))
	/* 0xE9: JMP rel? */ SPECIAL(INST_JMP_DIRECT, IMM(PREFIX_OPERAND_SIZE))
#ifdef _WIN64
	/* 0xEA: INVALID */ INVALID()
#else
	/* 0xEA: JMP FAR ptr16:? */ UNSUPPORTED()
#endif
	/* 0xEB: JMP rel8 */ SPECIAL(INST_JMP_DIRECT, IMM(1))
	/* 0xEC: IN AL, DX */ INST_UNTESTED(READ(REG_DX), WRITE(REG_AX))
	/* 0xED: IN AX/EAX, DX */ INST_UNTESTED(READ(REG_DX), WRITE(REG_AX))
	/* 0xEE: OUT DX, AL */ INST_UNTESTED(READ(REG_DX | REG_AX))
	/* 0xEF: OUT DX, AX/EAX */ INST_UNTESTED(READ(REG_DX | REG_AX))
	/* 0xF0: LOCK prefix */ INVALID()
	/* 0xF1: ??? */ UNKNOWN()
	/* 0xF2: ??? */ UNKNOWN()
	/* 0xF3: ??? */ UNKNOWN()
	/* 0xF4: HLT */ INST_UNTESTED()
	/* 0xF5: CMC */ INST_UNTESTED()
	/* 0xF6 */ EXTENSION(F6)
	/* 0xF7 */ EXTENSION(F7)
	/* 0xF8: CLC */ INST()
	/* 0xF9: STC */ INST()
	/* 0xFA: CLI */ INST()
	/* 0xFB: STI */ INST()
	/* 0xFC: CLD */ INST()
	/* 0xFD: STD */ INST()
	/* [GRP4]: 0/INC, /DEC */
	/* 0xFE: [GRP4] r/m8 */ INST_UNTESTED(MODRM(), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xFF */ EXTENSION(FF)
};

/* Instructions with 0F prefix */
static const struct instruction_desc two_byte_inst[256] =
{
	/* 0x00: [GRP6]
	0: SLDT r/m16
	1: STR r/m16
	2: LLDT r/m16
	3: LTR r/m16
	4: VERR r/m16
	5: VERW r/m16 */ UNSUPPORTED()
	/* 0x01: [GRP7]
	0: SGDT m
	1: SIDT m
	2: LGDT m16&32; LGDT m16&64
	3: LIDT m16&32; LIDT m16&64
	4: SMSW r/m16; SMSW r32/m16
	6: LMSW r/m16
	7: INVLPG */ UNSUPPORTED()
	/* 0x02: LAR r16, r16/m16; LAR reg, r32/m16 */ UNSUPPORTED()
	/* 0x03: LSL r?, r?/m16 */ UNSUPPORTED()
	/* 0x04: ??? */ UNKNOWN()
	/* 0x05: SYSCALL */ UNSUPPORTED()
	/* 0x06: CLTS */ UNSUPPORTED()
	/* 0x07: SYSRET */ UNSUPPORTED()
	/* 0x08: INVD */ UNSUPPORTED()
	/* 0x09: WBINVD */ UNSUPPORTED()
	/* 0x0A: ??? */ UNKNOWN()
	/* 0x0B: UD2 */ INVALID()
	/* 0x0C: ??? */ UNKNOWN()
	/* 0x0D: ??? */ UNKNOWN()
	/* 0x0E: ??? */ UNKNOWN()
	/* 0x0F: ??? */ UNKNOWN()
	/* 0x10: ??? */ UNKNOWN()
	/* 0x11: ??? */ UNKNOWN()
	/* 0x12: ??? */ UNKNOWN()
	/* 0x13: ??? */ UNKNOWN()
	/* 0x14: ??? */ UNKNOWN()
	/* 0x15: ??? */ UNKNOWN()
	/* 0x16: ??? */ UNKNOWN()
	/* 0x17: ??? */ UNKNOWN()
	/* 0x18: ??? */ UNKNOWN()
	/* 0x19: ??? */ UNKNOWN()
	/* 0x1A: ??? */ UNKNOWN()
	/* 0x1B: ??? */ UNKNOWN()
	/* 0x1C: ??? */ UNKNOWN()
	/* 0x1D: ??? */ UNKNOWN()
	/* 0x1E: ??? */ UNKNOWN()
	/* 0x1F: NOP r/m? */ INST_UNTESTED() /* TODO */
	/* 0x20: MOV r32, CR0-CR7; MOV r64, CR0-CR7 */ UNSUPPORTED()
	/* 0x21: MOV r32, DR0-DR7; MOV r64, DR0-DR7 */ UNSUPPORTED()
	/* 0x22: MOV CR0-CR7, r32; MOV CR0-CR7, r64 */ UNSUPPORTED()
	/* 0x23: MOV DR0-DR7, r32; MOV DR0-DR7, r64 */ UNSUPPORTED()
	/* 0x24: ??? */ UNKNOWN()
	/* 0x25: ??? */ UNKNOWN()
	/* 0x26: ??? */ UNKNOWN()
	/* 0x27: ??? */ UNKNOWN()
	/* 0x28: ??? */ UNKNOWN()
	/* 0x29: ??? */ UNKNOWN()
	/* 0x2A: ??? */ UNKNOWN()
	/* 0x2B: ??? */ UNKNOWN()
	/* 0x2C: ??? */ UNKNOWN()
	/* 0x2D: ??? */ UNKNOWN()
	/* 0x2E: ??? */ UNKNOWN()
	/* 0x2F: ??? */ UNKNOWN()
	/* 0x30: WRMSR */ PRIVILEGED()
	/* 0x31: RDTSC */ INST(WRITE(REG_AX | REG_DX))
	/* 0x32: RDMSR */ PRIVILEGED()
	/* 0x33: RDPMC */ INST_UNTESTED(READ(REG_CX), WRITE(REG_AX | REG_DX))
	/* 0x34: SYSENTER */ UNSUPPORTED()
	/* 0x35: SYSEXIT */ UNSUPPORTED()
	/* 0x36: ??? */ UNKNOWN()
	/* 0x37: ??? */ UNKNOWN()
	/* 0x38: ??? */ UNKNOWN()
	/* 0x39: ??? */ UNKNOWN()
	/* 0x3A: ??? */ UNKNOWN()
	/* 0x3B: ??? */ UNKNOWN()
	/* 0x3C: ??? */ UNKNOWN()
	/* 0x3D: ??? */ UNKNOWN()
	/* 0x3E: ??? */ UNKNOWN()
	/* 0x3F: ??? */ UNKNOWN()
	/* 0x40: CMOVO r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x41: CMOVNO r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x42: CMOVB/CMOVNAE/CMOVC r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x43: CMOVAE/CMOVNB/CMOVNC r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x44: CMOVE/CMOVZ r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x45: CMOVNE/CMOVNZ r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x46: CMOVBE/CMOVNA r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x47: CMOVA/CMOVNBE r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x48: CMOVS r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x49: CMOVNS r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4A: CMOVP/CMOVPE r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4B: CMOVNP/CMOVPO r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4C: CMOVL/CMOVNGE r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4D: CMOVGE/CMOVNL r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4E: CMOVLE/CMOVNG r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4F: CMOVG/CMOVNLE r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x50: ??? */ UNKNOWN()
	/* 0x51: ??? */ UNKNOWN()
	/* 0x52: ??? */ UNKNOWN()
	/* 0x53: ??? */ UNKNOWN()
	/* 0x54: ??? */ UNKNOWN()
	/* 0x55: ??? */ UNKNOWN()
	/* 0x56: ??? */ UNKNOWN()
	/* 0x57: ??? */ UNKNOWN()
	/* 0x58: ??? */ UNKNOWN()
	/* 0x59: ??? */ UNKNOWN()
	/* 0x5A: ??? */ UNKNOWN()
	/* 0x5B: ??? */ UNKNOWN()
	/* 0x5C: ??? */ UNKNOWN()
	/* 0x5D: ??? */ UNKNOWN()
	/* 0x5E: ??? */ UNKNOWN()
	/* 0x5F: ??? */ UNKNOWN()
	/* 0x60: ??? */ UNKNOWN()
	/* 0x61: ??? */ UNKNOWN()
	/* 0x62: ??? */ UNKNOWN()
	/* 0x63: ??? */ UNKNOWN()
	/* 0x64: ??? */ UNKNOWN()
	/* 0x65: ??? */ UNKNOWN()
	/* 0x66: ??? */ UNKNOWN()
	/* 0x67: ??? */ UNKNOWN()
	/* 0x68: ??? */ UNKNOWN()
	/* 0x69: ??? */ UNKNOWN()
	/* 0x6A: ??? */ UNKNOWN()
	/* 0x6B: ??? */ UNKNOWN()
	/* 0x6C: ??? */ UNKNOWN()
	/* 0x6D: ??? */ UNKNOWN()
	/* 0x6E: ??? */ UNKNOWN()
	/* 0x6F: ??? */ UNKNOWN()
	/* 0x70: ??? */ UNKNOWN()
	/* 0x71: ??? */ UNKNOWN()
	/* 0x72: ??? */ UNKNOWN()
	/* 0x73: ??? */ UNKNOWN()
	/* 0x74: ??? */ UNKNOWN()
	/* 0x75: ??? */ UNKNOWN()
	/* 0x76: ??? */ UNKNOWN()
	/* 0x77: EMMS */ UNSUPPORTED()
	/* 0x78: ??? */ UNKNOWN()
	/* 0x79: ??? */ UNKNOWN()
	/* 0x7A: ??? */ UNKNOWN()
	/* 0x7B: ??? */ UNKNOWN()
	/* 0x7C: ??? */ UNKNOWN()
	/* 0x7D: ??? */ UNKNOWN()
	/* 0x7E: ??? */ UNKNOWN()
	/* 0x7F: ??? */ UNKNOWN()
	/* 0x80: JO rel? */ SPECIAL(INST_JCC + 0, IMM(PREFIX_OPERAND_SIZE))
	/* 0x81: JNO rel? */ SPECIAL(INST_JCC + 1, IMM(PREFIX_OPERAND_SIZE))
	/* 0x82: JB/JC/JNAE rel? */ SPECIAL(INST_JCC + 2, IMM(PREFIX_OPERAND_SIZE))
	/* 0x83: JAE/JNB/JNC rel? */ SPECIAL(INST_JCC + 3, IMM(PREFIX_OPERAND_SIZE))
	/* 0x84: JE/JZ rel? */ SPECIAL(INST_JCC + 4, IMM(PREFIX_OPERAND_SIZE))
	/* 0x85: JNE/JNZ rel? */ SPECIAL(INST_JCC + 5, IMM(PREFIX_OPERAND_SIZE))
	/* 0x86: JBE/JNA rel? */ SPECIAL(INST_JCC + 6, IMM(PREFIX_OPERAND_SIZE))
	/* 0x87: JA/JNBE rel? */ SPECIAL(INST_JCC + 7, IMM(PREFIX_OPERAND_SIZE))
	/* 0x88: JS rel? */ SPECIAL(INST_JCC + 8, IMM(PREFIX_OPERAND_SIZE))
	/* 0x89: JNS rel? */ SPECIAL(INST_JCC + 9, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8A: JP/JPE rel? */ SPECIAL(INST_JCC + 10, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8B: JNP/JPO rel? */ SPECIAL(INST_JCC + 11, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8C: JL/JNGE rel? */ SPECIAL(INST_JCC + 12, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8D: JGE/JNL rel? */ SPECIAL(INST_JCC + 13, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8E: JLE/JNG rel? */ SPECIAL(INST_JCC + 14, IMM(PREFIX_OPERAND_SIZE))
	/* 0x8F: JG/JNLE rel? */ SPECIAL(INST_JCC + 15, IMM(PREFIX_OPERAND_SIZE))
	/* 0x90: SETO r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x91: SETNO r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x92: SETB/SETC/SETNAE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x93: SETAE/SETNB/SETNC r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x94: SETE/SETZ r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x95: SETNE/SETNZ r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x96: SETBE/SETNA r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x97: SETA/SETNBE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x98: SETS r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x99: SETNS r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9A: SETP/SETPE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9B: SETNP/SETPO r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9C: SETL/SETNGE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9D: SETGE/SETNL r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9E: SETLE/SETNG r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0x9F: SETG/SETNLE r/m8 */ INST(MODRM(), WRITE(MODRM_RM))
	/* 0xA0: ??? */ UNKNOWN()
	/* 0xA1: POP FS */ UNSUPPORTED()
	/* 0xA2: CPUID */ INST(READ(REG_AX | REG_BX | REG_CX | REG_DX), WRITE(REG_AX | REG_BX | REG_CX | REG_DX))
	/* 0xA3: BT r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0xA4: SHLD r/m?, r?, imm8 */ INST_UNTESTED(MODRM(), IMM(1), READ(MODRM_RM | MODRM_R), WRITE(MODRM_RM))
	/* 0xA5: SHLD r/m?, r?, CL */ INST_UNTESTED(MODRM(), READ(MODRM_RM | MODRM_R | REG_CX), WRITE(MODRM_RM))
	/* 0xA6: ??? */ UNKNOWN()
	/* 0xA7: ??? */ UNKNOWN()
	/* 0xA8: ??? */ UNKNOWN()
	/* 0xA9: POP GS */ UNSUPPORTED()
#ifdef _WIN64
	/* 0xAA: INVALID */ INVALID()
#else
	/* 0xAA: RSM */ INST_UNTESTED()
#endif
	/* 0xAB: BTS r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0xAC: SHRD r/m?, r?, imm8 */ INST_UNTESTED(MODRM(), IMM(1), READ(MODRM_RM | MODRM_R), WRITE(MODRM_RM))
	/* 0xAD: SHRD r/m?, r?, CL */ INST_UNTESTED(MODRM(), READ(MODRM_RM | MODRM_R | REG_CX), WRITE(MODRM_RM))
	/* 0xAE:
	3/5: LFENCE
	3/6: MFENCE
	3/7: SFENCE
	mem/4: XSAVE mem
	mem/5: XRSTOR mem
	mem/6: XSAVEOPT mem
	mem/7: CLFLUSH m8 */ UNSUPPORTED()
	/* 0xAF: IMUL r?, r/m? */ INST(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xB0: CMPXCHG r/m8, r8 */ INST(MODRM(), READ(MODRM_R | MODRM_RM | REG_AX), WRITE(MODRM_RM | REG_AX))
	/* 0xB1: CMPXCHG r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM | REG_AX), WRITE(MODRM_RM | REG_AX))
	/* 0xB2: LSS r?, m16:? */ UNSUPPORTED()
	/* 0xB3: BTR r/m?, r? */ INST(MODRM(), IMM(1), READ(MODRM_RM))
	/* 0xB4: LFS r?, m16:? */ UNSUPPORTED()
	/* 0xB5: LGS r?, m16:? */ UNSUPPORTED()
	/* 0xB6: MOVZX r?, r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xB7: MOVZX r?, r/m16 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xB8: ??? */ UNKNOWN()
	/* 0xB9: ??? */ UNKNOWN()
	/* GRP8: 4/BT, 5/BTS, 6/BTR, 7/BTC */
	/* 0xBA: [GRP8] r/m?, imm8 */ INST_UNTESTED(MODRM(), IMM(1), READ(MODRM_RM))
	/* 0xBB: BTC r/m?, r? */ INST(MODRM(), READ(MODRM_R | MODRM_RM))
	/* 0xBC: BSF r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xBD: BSR r?, r/m? */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xBE: MOVSX r?, r/m8 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xBF: MOVSX r?, r/m16 */ INST(MODRM(), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xC0: XADD r/m8, r8 */ INST_UNTESTED(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0xC1: XADD r/m?, r? */ INST_UNTESTED(MODRM(), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0xC2: ??? */ UNKNOWN()
	/* 0xC3: ??? */ UNKNOWN()
	/* 0xC4: ??? */ UNKNOWN()
	/* 0xC5: ??? */ UNKNOWN()
	/* 0xC6: ??? */ UNKNOWN()
	/* 0xC7:
	1: CMPXCHG8B m64/m128
	5: XSAVES mem; XSAVES64 mem */ UNSUPPORTED()
	/* NOTE: The read and write information of these are not very accurate */
	/* 0xC8: BSWAP ?AX/R8? */ INST(READ(REG_AX | REG_R8), WRITE(REG_AX | REG_R8))
	/* 0xC9: BSWAP ?CX/R9? */ INST(READ(REG_CX | REG_R9), WRITE(REG_CX | REG_R9))
	/* 0xCA: BSWAP ?DX/R10? */ INST(READ(REG_DX | REG_R10), WRITE(REG_DX | REG_R10))
	/* 0xCB: BSWAP ?BX/R11? */ INST(READ(REG_BX | REG_R11), WRITE(REG_BX | REG_R11))
	/* 0xCC: BSWAP ?SP/R12? */ INST(READ(REG_SP | REG_R12), WRITE(REG_SP | REG_R12))
	/* 0xCD: BSWAP ?BP/R13? */ INST(READ(REG_BP | REG_R13), WRITE(REG_BP | REG_R13))
	/* 0xCE: BSWAP ?SI/R14? */ INST(READ(REG_SI | REG_R14), WRITE(REG_SI | REG_R14))
	/* 0xCF: BSWAP ?DI/R15? */ INST(READ(REG_DI | REG_R15), WRITE(REG_DI | REG_R15))
	/* 0xD0: ??? */ UNKNOWN()
	/* 0xD1: ??? */ UNKNOWN()
	/* 0xD2: ??? */ UNKNOWN()
	/* 0xD3: ??? */ UNKNOWN()
	/* 0xD4: ??? */ UNKNOWN()
	/* 0xD5: ??? */ UNKNOWN()
	/* 0xD6: ??? */ UNKNOWN()
	/* 0xD7: ??? */ UNKNOWN()
	/* 0xD8: ??? */ UNKNOWN()
	/* 0xD9: ??? */ UNKNOWN()
	/* 0xDA: ??? */ UNKNOWN()
	/* 0xDB: ??? */ UNKNOWN()
	/* 0xDC: ??? */ UNKNOWN()
	/* 0xDD: ??? */ UNKNOWN()
	/* 0xDE: ??? */ UNKNOWN()
	/* 0xDF: ??? */ UNKNOWN()
	/* 0xE0: ??? */ UNKNOWN()
	/* 0xE1: ??? */ UNKNOWN()
	/* 0xE2: ??? */ UNKNOWN()
	/* 0xE3: ??? */ UNKNOWN()
	/* 0xE4: ??? */ UNKNOWN()
	/* 0xE5: ??? */ UNKNOWN()
	/* 0xE6: ??? */ UNKNOWN()
	/* 0xE7: ??? */ UNKNOWN()
	/* 0xE8: ??? */ UNKNOWN()
	/* 0xE9: ??? */ UNKNOWN()
	/* 0xEA: ??? */ UNKNOWN()
	/* 0xEB: ??? */ UNKNOWN()
	/* 0xEC: ??? */ UNKNOWN()
	/* 0xED: ??? */ UNKNOWN()
	/* 0xEE: ??? */ UNKNOWN()
	/* 0xEF: ??? */ UNKNOWN()
	/* 0xF0: ??? */ UNKNOWN()
	/* 0xF1: ??? */ UNKNOWN()
	/* 0xF2: ??? */ UNKNOWN()
	/* 0xF3: ??? */ UNKNOWN()
	/* 0xF4: ??? */ UNKNOWN()
	/* 0xF5: ??? */ UNKNOWN()
	/* 0xF6: ??? */ UNKNOWN()
	/* 0xF7: ??? */ UNKNOWN()
	/* 0xF8: ??? */ UNKNOWN()
	/* 0xF9: ??? */ UNKNOWN()
	/* 0xFA: ??? */ UNKNOWN()
	/* 0xFB: ??? */ UNKNOWN()
	/* 0xFC: ??? */ UNKNOWN()
	/* 0xFD: ??? */ UNKNOWN()
	/* 0xFE: ??? */ UNKNOWN()
	/* 0xFF: ??? */ UNKNOWN()
};
