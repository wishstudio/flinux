/* Instruction description tables */
#define INST_TYPE_UNKNOWN		0 /* Unknown/not implemented */
#define INST_TYPE_INVALID		1 /* Invalid instruction */
#define INST_TYPE_UNSUPPORTED	2 /* Unsupported instruction */
#define INST_TYPE_NOP			3 /* Instruction which has no extra operand bytes */
#define INST_TYPE_IMMEDIATE		4 /* Instruction containing some operand bytes*/
#define INST_TYPE_MODRM			5 /* Instruction containing a memory address in ModR/M opcode */
#define INST_TYPE_MOV_MOFFSET	6 /* MOV moffset series instructions */
#define INST_TYPE_EXTENSION(x)	(32 + (x)) /* Instruction with opcode extension */

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
#define MODRM_R			0x01000000 /* R field of ModR/M */
#define MODRM_RM_R		0x02000000 /* Register type of ModR/M R/M field */
#define MODRM_RM_M		0x04000000 /* Memory type of ModR/M R/M field */
#define MODRM_RM		MODRM_RM_R | MODRM_RM_M /* R/M field of ModR/M */

#define PREFIX_OPERAND_SIZE -1 /* Indicate imm_bytes is 2 or 4 bytes depends on operand size prefix */
#define PREFIX_OPERAND_SIZE_64 -2 /* Indicate imm_bytes is 2 or 4 or 8 bytes depends on operand size prefix */
struct instruction_desc
{
	int type; /* Instruction type */
	int imm_bytes; /* Bytes after ModR/M opcode, or PREFIX_OPERAND_SIZE(_64) */
	int read_regs; /* The bitmask of registers which are read from */
	int write_regs; /* The bitmask of registers which are written to */
};
#define INST(x)			{ x },
#define UNKNOWN()		.type = INST_TYPE_UNKNOWN,
#define UNSUPPORTED()	.type = INST_TYPE_UNSUPPORTED,
#define INVALID()		.type = INST_TYPE_INVALID,
#define NOP()			.type = INST_TYPE_NOP,
#define IMM(i)			.type = INST_TYPE_IMMEDIATE, .imm_bytes = (i),
#define MODRM(i)		.type = INST_TYPE_MODRM, .imm_bytes = (i),
#define MOV_MOFFSET()	.type = INST_TYPE_MOV_MOFFSET,
#define EXTENSION(x)	.type = INST_TYPE_EXTENSION(x),
#define READ(x)			.read_regs = (x),
#define WRITE(x)		.write_regs = (x),

static const struct instruction_desc one_byte_inst[256] =
{
	/* 0x00: ADD r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x01: ADD r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x02: ADD r8, r/m8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x03: ADD r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x04: ADD AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x05: ADD ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x06: ??? */ INST(UNKNOWN())
#ifdef _WIN64
	/* 0x07: INVALID */ INST(INVALID())
#else
	/* 0x07: POP ES */ INST(UNSUPPORTED())
#endif
	/* 0x08: OR r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x09: OR r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x0A: OR r8, r/m8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0B: OR r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x0C: OR AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x0D: OR ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x0E: ??? */ INST(UNKNOWN())
	/* 0x0F: ??? */ INST(UNKNOWN())
	/* 0x10: ADC r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x11: ADC r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x12: ADC r8, r/m8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x13: ADC r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x14: ADC AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x15: ADC ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x16: ??? */ INST(UNKNOWN())
#ifdef _WIN64
	/* 0x17: INVALID */ INST(INVALID())
#else
	/* 0x17: POP SS */ INST(UNSUPPORTED())
#endif
	/* 0x18: SBB r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x19: SBB r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x1A: SBB r8, r/m8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x1B: SBB r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x1C: SBB AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x1D: SBB ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x1E: ??? */ INST(UNKNOWN())
#ifdef _WIN64
	/* 0x1F: INVALID */ INST(INVALID())
#else
	/* 0x1F: POP DS */ INST(UNSUPPORTED())
#endif
	/* 0x20: AND r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x21: AND r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x22: AND r8, r/m8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x23: AND r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x24: AND AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x25: AND ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x26: ES segment prefix */ INST(INVALID())
#ifdef _WIN64
	/* 0x27: INVALID */ INST(INVALID())
#else
	/* 0x27: DAA */ INST(NOP(), READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0x28: SUB r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x29: SUB r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x2A: SUB r8, r/m8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x2B: SUB r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x2C: SUB AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x2D: SUB ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x2E: CS segment prefix */ INST(INVALID())
#ifdef _WIN64
	/* 0x2F: INVALID */ INST(INVALID())
#else
	/* 0x2F: DAS */ INST(NOP(), READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0x30: XOR r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x31: XOR r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x32: XOR r8, r/m8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x33: XOR r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x34: XOR AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x35: XOR ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x36: SS segment prefix */ INST(INVALID())
#ifdef _WIN64
	/* 0x37: Invalid */ INST(INVALID())
#else
	/* 0x37: AAA */ INST(NOP(), READ(REG_AX), WRITE(REG_AX))
#endif
	/* 0x38: CMP r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x39: CMP r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_RM))
	/* 0x3A: CMP r8, r/m8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3B: CMP r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x3C: CMP AL, imm8 */ INST(IMM(1), READ(REG_AX), WRITE(REG_AX))
	/* 0x3D: CMP ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX), WRITE(REG_AX))
	/* 0x3E: DS segment prefix */ INST(INVALID())
#ifdef _WIN64
	/* 0x3F; INVALID */ INST(INVALID())
	/* 0x40: REX prefix */ INST(INVALID())
	/* 0x41: REX prefix */ INST(INVALID())
	/* 0x42: REX prefix */ INST(INVALID())
	/* 0x43: REX prefix */ INST(INVALID())
	/* 0x44: REX prefix */ INST(INVALID())
	/* 0x45: REX prefix */ INST(INVALID())
	/* 0x46: REX prefix */ INST(INVALID())
	/* 0x47: REX prefix */ INST(INVALID())
	/* 0x48: REX prefix */ INST(INVALID())
	/* 0x4A: REX prefix */ INST(INVALID())
	/* 0x4B: REX prefix */ INST(INVALID())
	/* 0x4C: REX prefix */ INST(INVALID())
	/* 0x4D: REX prefix */ INST(INVALID())
	/* 0x4E: REX prefix */ INST(INVALID())
	/* 0x4F: REX prefix */ INST(INVALID())
#else
	/* 0x3F: AAS */ INST(NOP(), READ(REG_AX), WRITE(REG_AX))
	/* 0x40: INC ?AX */ INST(NOP(), READ(REG_AX), WRITE(REG_AX))
	/* 0x41: INC ?CX */ INST(NOP(), READ(REG_CX), WRITE(REG_CX))
	/* 0x42: INC ?DX */ INST(NOP(), READ(REG_DX), WRITE(REG_DX))
	/* 0x43: INC ?BX */ INST(NOP(), READ(REG_BX), WRITE(REG_BX))
	/* 0x44: INC ?SP */ INST(NOP(), READ(REG_SP), WRITE(REG_SP))
	/* 0x45: INC ?BP */ INST(NOP(), READ(REG_BP), WRITE(REG_BP))
	/* 0x46: INC ?SI */ INST(NOP(), READ(REG_SI), WRITE(REG_SI))
	/* 0x47: INC ?DI */ INST(NOP(), READ(REG_DI), WRITE(REG_DI))
	/* 0x48: DEC ?AX */ INST(NOP(), READ(REG_AX), WRITE(REG_AX))
	/* 0x49: DEC ?CX */ INST(NOP(), READ(REG_CX), WRITE(REG_CX))
	/* 0x4A: DEC ?DX */ INST(NOP(), READ(REG_DX), WRITE(REG_DX))
	/* 0x4B: DEC ?BX */ INST(NOP(), READ(REG_BX), WRITE(REG_BX))
	/* 0x4C: DEC ?SP */ INST(NOP(), READ(REG_SP), WRITE(REG_SP))
	/* 0x4D: DEC ?BP */ INST(NOP(), READ(REG_BP), WRITE(REG_BP))
	/* 0x4E: DEC ?SI */ INST(NOP(), READ(REG_SI), WRITE(REG_SI))
	/* 0x4F: DEC ?DI */ INST(NOP(), READ(REG_DI), WRITE(REG_DI))
#endif
	/* NOTE: The read and write information of these are not very accurate */
	/* 0x50: PUSH ?AX/R8? */ INST(NOP(), READ(REG_SP | REG_AX | REG_R8), WRITE(REG_SP))
	/* 0x51: PUSH ?CX/R9? */ INST(NOP(), READ(REG_SP | REG_CX | REG_R9), WRITE(REG_SP))
	/* 0x52: PUSH ?DX/R10? */ INST(NOP(), READ(REG_SP | REG_DX | REG_R10), WRITE(REG_SP))
	/* 0x53: PUSH ?BX/R11? */ INST(NOP(), READ(REG_SP | REG_BX | REG_R11), WRITE(REG_SP))
	/* 0x54: PUSH ?SP/R12? */ INST(NOP(), READ(REG_SP | REG_SP | REG_R12), WRITE(REG_SP))
	/* 0x55: PUSH ?BP/R13? */ INST(NOP(), READ(REG_SP | REG_BP | REG_R13), WRITE(REG_SP))
	/* 0x56: PUSH ?SI/R14? */ INST(NOP(), READ(REG_SP | REG_SI | REG_R14), WRITE(REG_SP))
	/* 0x57: PUSH ?DI/R15? */ INST(NOP(), READ(REG_SP | REG_DI | REG_R15), WRITE(REG_SP))
	/* 0x58: POP ?AX/R8? */ INST(NOP(), READ(REG_SP), WRITE(REG_SP | REG_AX | REG_R8))
	/* 0x59: POP ?CX/R9? */ INST(NOP(), READ(REG_SP), WRITE(REG_SP | REG_CX | REG_R9))
	/* 0x5A: POP ?DX/R10? */ INST(NOP(), READ(REG_SP), WRITE(REG_SP | REG_DX | REG_R10))
	/* 0x5B: POP ?BX/R11? */ INST(NOP(), READ(REG_SP), WRITE(REG_SP | REG_BX | REG_R11))
	/* 0x5C: POP ?SP/R12? */ INST(NOP(), READ(REG_SP), WRITE(REG_SP | REG_SP | REG_R12))
	/* 0x5D: POP ?BP/R13? */ INST(NOP(), READ(REG_SP), WRITE(REG_SP | REG_BP | REG_R13))
	/* 0x5E: POP ?SI/R14? */ INST(NOP(), READ(REG_SP), WRITE(REG_SP | REG_SI | REG_R14))
	/* 0x5F: POP ?DI/R15? */ INST(NOP(), READ(REG_SP), WRITE(REG_SP | REG_DI | REG_R15))
#ifdef _WIN64
	/* 0x60: INVALID */ INST(INVALID())
	/* 0x61: INVALID */ INST(INVALID())
	/* 0x62: EVEX prefix */ INST(INVALID())
	/* 0x63: INVALID */ INST(INVALID())
#else
	/* 0x60: PUSHA_PUSHAD */ INST(NOP(), READ(REG_AX | REG_CX | REG_DX | REG_BX | REG_SP | REG_BP | REG_SI | REG_DI), WRITE(REG_SP))
	/* 0x61: POPA/POPAD */ INST(NOP(), READ(REG_SP), WRITE(REG_AX | REG_CX | REG_DX | REG_BX | REG_SP | REG_BP | REG_SI | REG_DI))
	/* 0x62: BOUND r?, m?&? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM_M))
	/* 0x63: ARPL r/m16, r16 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
#endif
	/* 0x64: FS segment prefix */ INST(INVALID())
	/* 0x65: GS segment prefix */ INST(INVALID())
	/* 0x66: ??? */ INST(UNKNOWN())
	/* 0x67: ??? */ INST(UNKNOWN())
	/* 0x68: ??? */ INST(UNKNOWN())
	/* 0x69: IMUL r?, r/m?, imm? */ INST(MODRM(PREFIX_OPERAND_SIZE), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x6A: ??? */ INST(UNKNOWN())
	/* 0x6B: IMUL r?, r/m?, imm8 */ INST(MODRM(1), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0x6C: INSB */ INST(UNSUPPORTED())
	/* 0x6D: INSW/INSD */ INST(UNSUPPORTED())
	/* 0x6E: OUTSB */ INST(UNSUPPORTED())
	/* 0x6F: OUTSW/OUTSD */ INST(UNSUPPORTED())
	/* 0x70: JO rel8 */ INST(IMM(1))
	/* 0x71: JNO rel8 */ INST(IMM(1))
	/* 0x72: JB/JC/JNAE rel8 */ INST(IMM(1))
	/* 0x73: JAE/JNB/JNC rel8 */ INST(IMM(1))
	/* 0x74: JE/JZ rel8 */ INST(IMM(1))
	/* 0x75: JNE/JNZ rel8 */ INST(IMM(1))
	/* 0x76: JBE/JNA rel8 */ INST(IMM(1))
	/* 0x77: JA/JNBE rel8 */ INST(IMM(1))
	/* 0x78: JS rel8 */ INST(IMM(1))
	/* 0x79: JNS rel8 */ INST(IMM(1))
	/* 0x7A: JP/JPE rel8 */ INST(IMM(1))
	/* 0x7B: JNP/JPO rel8 */ INST(IMM(1))
	/* 0x7C: JL/JNGE rel8 */ INST(IMM(1))
	/* 0x7D: JGE/JNL rel8 */ INST(IMM(1))
	/* 0x7E: JLE/JNG rel8 */ INST(IMM(1))
	/* 0x7F: JG/JNLE rel8 */ INST(IMM(1))
	/* [GRP1]: 0/ADD, 1/OR, 2/ADC, 3/SBB, 4/AND, 5/SUB, 6/XOR, 7/CMP */
	/* 0x80: [GRP1] r/m8, imm8 */ INST(MODRM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x81: [GRP1] r/m?, imm? */ INST(MODRM(PREFIX_OPERAND_SIZE), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x82: ??? */ INST(UNKNOWN())
	/* 0x83: [GRP1] r/m?, imm8 */ INST(MODRM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0x84: TEST r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM))
	/* 0x85: TEST r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM))
	/* 0x86: XCHG r8, r/m8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0x87: XCHG r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0x88: MOV r/m8, r8 */ INST(MODRM(0), READ(MODRM_R), WRITE(MODRM_RM))
	/* 0x89: MOV r/m?, r? */ INST(MODRM(0), READ(MODRM_R), WRITE(MODRM_RM))
	/* 0x8A: MOV r8, r/m8 */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x8B: MOV r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x8C: MOV r/m16, Sreg; MOV r/m64, Sreg */ INST(UNSUPPORTED())
	/* 0x8D: LEA r?, m */ INST(MODRM(0), READ(MODRM_RM_M), WRITE(MODRM_R))
	/* 0x8E: MOV Sreg, r/m16; MOV Sreg, r/m64 */ INST(UNSUPPORTED())
	/* 0x8F: POP r/m? */ INST(MODRM(0), READ(REG_SP), WRITE(REG_SP | MODRM_RM))
	/* NOTE: The read and write information of these are not very accurate */
	/* 0x90: XCHG ?AX, ?AX/R8?; NOP */ INST(NOP())
	/* 0x91: XCHG ?AX, ?CX/R9? */ INST(NOP(), READ(REG_AX | REG_CX | REG_R9), WRITE(REG_AX | REG_CX | REG_R9))
	/* 0x92: XCHG ?AX, ?DX/R10? */ INST(NOP(), READ(REG_AX | REG_DX | REG_R10), WRITE(REG_AX | REG_DX | REG_R10))
	/* 0x93: XCHG ?AX, ?BX/R11? */ INST(NOP(), READ(REG_AX | REG_BX | REG_R11), WRITE(REG_AX | REG_BX | REG_R11))
	/* 0x94: XCHG ?AX, ?SP/R12? */ INST(NOP(), READ(REG_AX | REG_SP | REG_R12), WRITE(REG_AX | REG_SP | REG_R12))
	/* 0x95: XCHG ?AX, ?BP/R13? */ INST(NOP(), READ(REG_AX | REG_BP | REG_R13), WRITE(REG_AX | REG_BP | REG_R13))
	/* 0x96: XCHG ?AX, ?SI/R14? */ INST(NOP(), READ(REG_AX | REG_SI | REG_R14), WRITE(REG_AX | REG_SI | REG_R14))
	/* 0x97: XCHG ?AX, ?DI/R15? */ INST(NOP(), READ(REG_AX | REG_DI | REG_R15), WRITE(REG_AX | REG_DI | REG_R15))
	/* 0x98: CBW; CWDE; CDQE */ INST(NOP(), READ(REG_AX), WRITE(REG_AX))
	/* 0x99: CWD; CDQ; CQO */ INST(NOP(), READ(REG_AX), WRITE(REG_AX | REG_DX))
#ifdef _WIN64
	/* 0x9A: INVALID */ INST(INVALID())
#else
	/* 0x9A: CALL FAR ptr16:? */ INST(UNSUPPORTED())
#endif
	/* 0x9B: FWAIT */ INST(NOP())
	/* 0x9C: PUSHF/PUSHFD/PUSHFQ */ INST(NOP(), READ(REG_SP), WRITE(REG_SP))
	/* 0x9D: POPF/POPFD/POPFQ */ INST(NOP(), READ(REG_SP), WRITE(REG_SP))
#ifdef _WIN64
	/* 0x9E: INVALID */ INST(INVALID())
	/* 0x9F: INVALID */ INST(INVALID())
#else
	/* 0x9E: SAHF */ INST(NOP(), READ(REG_AX))
	/* 0x9F: LAHF */ INST(NOP(), WRITE(REG_AX))
#endif
	/* 0xA0: MOV AL, moffs8 */ INST(MOV_MOFFSET())
	/* 0xA1: MOV AX, moffs16; MOV EAX, moffs32 */ INST(MOV_MOFFSET())
	/* 0xA2: MOV moffs8, AL */ INST(MOV_MOFFSET())
	/* 0xA3: MOV moffs16, AX; MOV moffs32, EAX */ INST(MOV_MOFFSET())
	/* 0xA4: MOVSB */ INST(UNSUPPORTED())
	/* 0xA5: MOVSW/MOVSD/MOVSQ */ INST(UNSUPPORTED())
	/* 0xA6: CMPSB */ INST(UNSUPPORTED())
	/* 0xA7: CMPSW/CMPSD/CMPSDQ */ INST(UNSUPPORTED())
	/* 0xA8: TEST AL, imm8 */ INST(IMM(1), READ(REG_AX))
	/* 0xA9: TEST ?AX, imm? */ INST(IMM(PREFIX_OPERAND_SIZE), READ(REG_AX))
	/* 0xAA: STOSB */ INST(UNSUPPORTED())
	/* 0xAB: STOSW/STOSD/STOSQ */ INST(UNSUPPORTED())
	/* 0xAC: LODSB */ INST(UNSUPPORTED())
	/* 0xAD: LODSW/LODSD/LODSQ */ INST(UNSUPPORTED())
	/* 0xAE: SCASB */ INST(UNSUPPORTED())
	/* 0xAF: SCASW/SCASD/SCASQ */ INST(UNSUPPORTED())
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
	/* 0xC0: [GRP2] r/m8, imm8 */ INST(MODRM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xC1: [GRP2] r/m?, imm8 */ INST(MODRM(1), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xC2: RET imm16 */ INST(IMM(2))
	/* 0xC3: RET */ INST(NOP())
#ifdef _WIN64
	/* 0xC4: INVALID */ INST(INVALID())
	/* 0xC5: INVALID */ INST(INVALID())
#else
	/* 0xC4: LES r?, m16:? */ INST(UNSUPPORTED())
	/* 0xC5: LDS r?, m16:? */ INST(UNSUPPORTED())
#endif
	/* 0xC6: 0/MOV r/m8, imm8 */ INST(MODRM(1), WRITE(MODRM_RM))
	/* 0xC7: 0/MOV r/m?, imm? */ INST(MODRM(PREFIX_OPERAND_SIZE), WRITE(MODRM_RM))
	/* 0xC8: ENTER */ INST(UNSUPPORTED())
	/* 0xC9: LEAVE */ INST(NOP(), READ(REG_BP), WRITE(REG_BP | REG_SP))
	/* 0xCA: RET FAR imm16 */ INST(IMM(2))
	/* 0xCB: RET FAR */ INST(NOP())
	/* 0xCC: INT 3 */ INST(NOP())
	/* 0xCD: INT */ INST(IMM(1))
#ifdef _WIN64
	/* 0xCE: INVALID */ INST(INVALID())
#else
	/* 0xCE: INTO */ INST(NOP())
#endif
	/* 0xCF: IRET/IRETD/IRETQ */ INST(NOP())
	/* 0xD0: [GRP2] r/m8, 1 */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xD1: [GRP2] r/m?, 1 */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xD2: [GRP2] r/m8, CL */ INST(MODRM(0), READ(MODRM_RM | REG_CX), WRITE(MODRM_RM))
	/* 0xD3: [GRP2] r/m?, CL */ INST(MODRM(0), READ(MODRM_RM | REG_CX), WRITE(MODRM_RM))
#ifdef _WIN64
	/* 0xD4: INVALID */ INST(INVALID())
	/* 0xD5: INVALID */ INST(INVALID())
#else
	/* 0xD4: AAM */ INST(IMM(1), READ(REG_A), WRITE(REG_A))
	/* 0xD5: AAD */ INST(IMM(1), READ(REG_A), WRITE(REG_A))
#endif
	/* 0xD6: ??? */ INST(UNKNOWN())
	/* 0xD7: XLAT */ INST(UNSUPPORTED())
	/* 0xD8: (x87 escape) */ INST(UNKNOWN())
	/* 0xD9: (x87 escape) */ INST(UNKNOWN())
	/* 0xDA: (x87 escape) */ INST(UNKNOWN())
	/* 0xDB: (x87 escape) */ INST(UNKNOWN())
	/* 0xDC: (x87 escape) */ INST(UNKNOWN())
	/* 0xDD: (x87 escape) */ INST(UNKNOWN())
	/* 0xDE: (x87 escape) */ INST(UNKNOWN())
	/* 0xDF: (x87 escape) */ INST(UNKNOWN())
	/* 0xE0: LOOPNE rel8 */ INST(IMM(1), READ(REG_CX), WRITE(REG_CX))
	/* 0xE1: LOOPE rel8 */ INST(IMM(1), READ(REG_CX), WRITE(REG_CX))
	/* 0xE2: LOOP rel8 */ INST(IMM(1), READ(REG_CX), WRITE(REG_CX))
	/* 0xE3: JCXZ/JECXZ rel8 */ INST(IMM(1), READ(REG_CX))
	/* 0xE4: IN AL, imm8 */ INST(IMM(1), WRITE(REG_AX))
	/* 0xE5: IN AX/EAX, imm8 */ INST(IMM(1), WRITE(REG_AX))
	/* 0xE6: OUT imm8, AL */ INST(IMM(1), READ(REG_AX))
	/* 0xE7: OUT imm8, AX/EAX */ INST(IMM(1), READ(REG_AX))
	/* 0xE8: CALL rel16/rel32 */ INST(UNSUPPORTED())
	/* 0xE9: JMP rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
#ifdef _WIN64
	/* 0xEA: INVALID */ INST(INVALID())
#else
	/* 0xEA: JMP FAR ptr16:? */ INST(UNSUPPORTED())
#endif
	/* 0xEB: JMP rel8 */ INST(IMM(1))
	/* 0xEC: IN AL, DX */ INST(NOP(), READ(REG_DX), WRITE(REG_AX))
	/* 0xED: IN AX/EAX, DX */ INST(NOP(), READ(REG_DX), WRITE(REG_AX))
	/* 0xEE: OUT DX, AL */ INST(NOP(), READ(REG_DX | REG_AX))
	/* 0xEF: OUT DX, AX/EAX */ INST(NOP(), READ(REG_DX | REG_AX))
	/* 0xF0: LOCK prefix */ INST(INVALID())
	/* 0xF1: ??? */ INST(UNKNOWN())
	/* 0xF2: ??? */ INST(UNKNOWN())
	/* 0xF3: ??? */ INST(UNKNOWN())
	/* 0xF4: HLT */ INST(NOP())
	/* 0xF5: CMC */ INST(NOP())
	/* [GRP3]: 0/TEST, 2/NOT, 3/NEG, 4/MUL, 5/IMUL, 6/DIV, 7/IDIV */
	/* 0xF6: [GRP3] */ INST(UNSUPPORTED())
	/* 0xF7: [GRP3] */ INST(UNSUPPORTED())
	/* 0xF8: CLC */ INST(NOP())
	/* 0xF9: STC */ INST(NOP())
	/* 0xFA: CLI */ INST(NOP())
	/* 0xFB: STI */ INST(NOP())
	/* 0xFC: CLD */ INST(NOP())
	/* 0xFD: STD */ INST(NOP())
	/* [GRP4]: 0/INC, /DEC */
	/* 0xFE: [GRP4] r/m8 */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_RM))
	/* 0xFF: [GRP5]
	0: INC r/m16; INC r/m32
	1: DEC r/m16; DEC r/m32
	2: CALL r/m16; CALL r/m32
	3: CALL FAR m16:16; CALL FAR m16:32
	4: JMP r/m32; JMP r/m64
	5: JMP FAR m16:16; JMP FAR m16:32
	6: PUSH r/m16; PUSH r/m32 */ INST(EXTENSION(5))
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
	5: VERW r/m16 */ INST(EXTENSION(6))
	/* 0x01: [GRP7]
	0: SGDT m
	1: SIDT m
	2: LGDT m16&32; LGDT m16&64
	3: LIDT m16&32; LIDT m16&64
	4: SMSW r/m16; SMSW r32/m16
	6: LMSW r/m16
	7: INVLPG */ INST(EXTENSION(7))
	/* 0x02: LAR r16, r16/m16; LAR reg, r32/m16 */ INST(UNSUPPORTED())
	/* 0x03: LSL r?, r?/m16 */ INST(UNSUPPORTED())
	/* 0x04: ??? */ INST(UNKNOWN())
	/* 0x05: SYSCALL */ INST(NOP())
	/* 0x06: CLTS */ INST(NOP())
	/* 0x07: SYSRET */ INST(NOP())
	/* 0x08: INVD */ INST(NOP())
	/* 0x09: WBINVD */ INST(NOP())
	/* 0x0A: ??? */ INST(UNKNOWN())
	/* 0x0B: UD2 */ INST(INVALID())
	/* 0x0C: ??? */ INST(UNKNOWN())
	/* 0x0D: ??? */ INST(UNKNOWN())
	/* 0x0E: ??? */ INST(UNKNOWN())
	/* 0x0F: ??? */ INST(UNKNOWN())
	/* 0x10: ??? */ INST(UNKNOWN())
	/* 0x11: ??? */ INST(UNKNOWN())
	/* 0x12: ??? */ INST(UNKNOWN())
	/* 0x13: ??? */ INST(UNKNOWN())
	/* 0x14: ??? */ INST(UNKNOWN())
	/* 0x15: ??? */ INST(UNKNOWN())
	/* 0x16: ??? */ INST(UNKNOWN())
	/* 0x17: ??? */ INST(UNKNOWN())
	/* 0x18: ??? */ INST(UNKNOWN())
	/* 0x19: ??? */ INST(UNKNOWN())
	/* 0x1A: ??? */ INST(UNKNOWN())
	/* 0x1B: ??? */ INST(UNKNOWN())
	/* 0x1C: ??? */ INST(UNKNOWN())
	/* 0x1D: ??? */ INST(UNKNOWN())
	/* 0x1E: ??? */ INST(UNKNOWN())
	/* 0x1F: NOP r/m? */ INST(NOP()) /* TODO */
	/* 0x20: MOV r32, CR0-CR7; MOV r64, CR0-CR7 */ INST(UNSUPPORTED())
	/* 0x21: MOV r32, DR0-DR7; MOV r64, DR0-DR7 */ INST(UNSUPPORTED())
	/* 0x22: MOV CR0-CR7, r32; MOV CR0-CR7, r64 */ INST(UNSUPPORTED())
	/* 0x23: MOV DR0-DR7, r32; MOV DR0-DR7, r64 */ INST(UNSUPPORTED())
	/* 0x24: ??? */ INST(UNKNOWN())
	/* 0x25: ??? */ INST(UNKNOWN())
	/* 0x26: ??? */ INST(UNKNOWN())
	/* 0x27: ??? */ INST(UNKNOWN())
	/* 0x28: ??? */ INST(UNKNOWN())
	/* 0x29: ??? */ INST(UNKNOWN())
	/* 0x2A: ??? */ INST(UNKNOWN())
	/* 0x2B: ??? */ INST(UNKNOWN())
	/* 0x2C: ??? */ INST(UNKNOWN())
	/* 0x2D: ??? */ INST(UNKNOWN())
	/* 0x2E: ??? */ INST(UNKNOWN())
	/* 0x2F: ??? */ INST(UNKNOWN())
	/* 0x30: WRMSR */ INST(NOP(), READ(REG_CX | REG_AX | REG_DX))
	/* 0x31: RDTSC */ INST(NOP(), WRITE(REG_AX | REG_DX))
	/* 0x32: RDMSR */ INST(NOP(), READ(REG_CX), WRITE(REG_AX | REG_DX))
	/* 0x33: RDPMC */ INST(NOP(), READ(REG_CX), WRITE(REG_AX | REG_DX))
	/* 0x34: SYSENTER */ INST(NOP())
	/* 0x35: SYSEXIT */ INST(NOP())
	/* 0x36: ??? */ INST(UNKNOWN())
	/* 0x37: ??? */ INST(UNKNOWN())
	/* 0x38: ??? */ INST(UNKNOWN())
	/* 0x39: ??? */ INST(UNKNOWN())
	/* 0x3A: ??? */ INST(UNKNOWN())
	/* 0x3B: ??? */ INST(UNKNOWN())
	/* 0x3C: ??? */ INST(UNKNOWN())
	/* 0x3D: ??? */ INST(UNKNOWN())
	/* 0x3E: ??? */ INST(UNKNOWN())
	/* 0x3F: ??? */ INST(UNKNOWN())
	/* 0x40: CMOVO r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x41: CMOVNO r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x42: CMOVB/CMOVNAE/CMOVC r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x43: CMOVAE/CMOVNB/CMOVNC r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x44: CMOVE/CMOVZ r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x45: CMOVNE/CMOVNZ r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x46: CMOVBE/CMOVNA r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x47: CMOVA/CMOVNBE r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x48: CMOVS r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x49: CMOVNS r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4A: CMOVP/CMOVPE r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4B: CMOVNP/CMOVPO r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4C: CMOVL/CMOVNGE r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4D: CMOVGE/CMOVNL r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4E: CMOVLE/CMOVNG r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x4F: CMOVG/CMOVNLE r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0x50: ??? */ INST(UNKNOWN())
	/* 0x51: ??? */ INST(UNKNOWN())
	/* 0x52: ??? */ INST(UNKNOWN())
	/* 0x53: ??? */ INST(UNKNOWN())
	/* 0x54: ??? */ INST(UNKNOWN())
	/* 0x55: ??? */ INST(UNKNOWN())
	/* 0x56: ??? */ INST(UNKNOWN())
	/* 0x57: ??? */ INST(UNKNOWN())
	/* 0x58: ??? */ INST(UNKNOWN())
	/* 0x59: ??? */ INST(UNKNOWN())
	/* 0x5A: ??? */ INST(UNKNOWN())
	/* 0x5B: ??? */ INST(UNKNOWN())
	/* 0x5C: ??? */ INST(UNKNOWN())
	/* 0x5D: ??? */ INST(UNKNOWN())
	/* 0x5E: ??? */ INST(UNKNOWN())
	/* 0x5F: ??? */ INST(UNKNOWN())
	/* 0x60: ??? */ INST(UNKNOWN())
	/* 0x61: ??? */ INST(UNKNOWN())
	/* 0x62: ??? */ INST(UNKNOWN())
	/* 0x63: ??? */ INST(UNKNOWN())
	/* 0x64: ??? */ INST(UNKNOWN())
	/* 0x65: ??? */ INST(UNKNOWN())
	/* 0x66: ??? */ INST(UNKNOWN())
	/* 0x67: ??? */ INST(UNKNOWN())
	/* 0x68: ??? */ INST(UNKNOWN())
	/* 0x69: ??? */ INST(UNKNOWN())
	/* 0x6A: ??? */ INST(UNKNOWN())
	/* 0x6B: ??? */ INST(UNKNOWN())
	/* 0x6C: ??? */ INST(UNKNOWN())
	/* 0x6D: ??? */ INST(UNKNOWN())
	/* 0x6E: ??? */ INST(UNKNOWN())
	/* 0x6F: ??? */ INST(UNKNOWN())
	/* 0x70: ??? */ INST(UNKNOWN())
	/* 0x71: ??? */ INST(UNKNOWN())
	/* 0x72: ??? */ INST(UNKNOWN())
	/* 0x73: ??? */ INST(UNKNOWN())
	/* 0x74: ??? */ INST(UNKNOWN())
	/* 0x75: ??? */ INST(UNKNOWN())
	/* 0x76: ??? */ INST(UNKNOWN())
	/* 0x77: EMMS */ INST(NOP())
	/* 0x78: ??? */ INST(UNKNOWN())
	/* 0x79: ??? */ INST(UNKNOWN())
	/* 0x7A: ??? */ INST(UNKNOWN())
	/* 0x7B: ??? */ INST(UNKNOWN())
	/* 0x7C: ??? */ INST(UNKNOWN())
	/* 0x7D: ??? */ INST(UNKNOWN())
	/* 0x7E: ??? */ INST(UNKNOWN())
	/* 0x7F: ??? */ INST(UNKNOWN())
	/* 0x80: JO rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x81: JNO rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x82: JB/JC/JNAE rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x83: JAE/JNB/JNC rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x84: JE/JZ rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x85: JNE/JNZ rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x86: JBE/JNA rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x87: JA/JNBE rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x88: JS rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x89: JNS rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x8A: JP/JPE rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x8B: JNP/JPO rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x8C: JL/JNGE rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x8D: JGE/JNL rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x8E: JLE/JNG rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x8F: JG/JNLE rel? */ INST(IMM(PREFIX_OPERAND_SIZE))
	/* 0x90: SETO r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x91: SETNO r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x92: SETB/SETC/SETNAE r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x93: SETAE/SETNB/SETNC r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x94: SETE/SETZ r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x95: SETNE/SETNZ r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x96: SETBE/SETNA r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x97: SETA/SETNBE r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x98: SETS r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x99: SETNS r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x9A: SETP/SETPE r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x9B: SETNP/SETPO r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x9C: SETL/SETNGE r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x9D: SETGE/SETNL r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x9E: SETLE/SETNG r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0x9F: SETG/SETNLE r/m8 */ INST(MODRM(0), WRITE(MODRM_RM))
	/* 0xA0: ??? */ INST(UNKNOWN())
	/* 0xA1: POP FS */ INST(NOP())
	/* 0xA2: CPUID */ INST(NOP(), READ(REG_AX | REG_BX | REG_CX | REG_DX), WRITE(REG_AX | REG_BX | REG_CX | REG_DX))
	/* 0xA3: BT r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM))
	/* 0xA4: SHLD r/m?, r?, imm8 */ INST(MODRM(1), READ(MODRM_RM | MODRM_R), WRITE(MODRM_RM))
	/* 0xA5: SHLD r/m?, r?, CL */ INST(MODRM(0), READ(MODRM_RM | MODRM_R | REG_CX), WRITE(MODRM_RM))
	/* 0xA6: ??? */ INST(UNKNOWN())
	/* 0xA7: ??? */ INST(UNKNOWN())
	/* 0xA8: ??? */ INST(UNKNOWN())
	/* 0xA9: POP GS */ INST(NOP())
#ifdef _WIN64
	/* 0xAA: INVALID */ INST(INVALID())
#else
	/* 0xAA: RSM */ INST(NOP())
#endif
	/* 0xAB: BTS r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM))
	/* 0xAC: SHRD r/m?, r?, imm8 */ INST(MODRM(1), READ(MODRM_RM | MODRM_R), WRITE(MODRM_RM))
	/* 0xAD: SHRD r/m?, r?, CL */ INST(MODRM(0), READ(MODRM_RM | MODRM_R | REG_CX), WRITE(MODRM_RM))
	/* 0xAE:
	3/5: LFENCE
	3/6: MFENCE
	3/7: SFENCE
	mem/4: XSAVE mem
	mem/5: XRSTOR mem
	mem/6: XSAVEOPT mem
	mem/7: CLFLUSH m8 */ INST(EXTENSION(15))
	/* 0xAF: IMUL r?, r/m? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R))
	/* 0xB0: CMPXCHG r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM | REG_AX), WRITE(MODRM_RM | REG_AX))
	/* 0xB1: CMPXCHG r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM | REG_AX), WRITE(MODRM_RM | REG_AX))
	/* 0xB2: LSS r?, m16:? */ INST(UNSUPPORTED())
	/* 0xB3: BTR r/m?, r? */ INST(MODRM(1), READ(MODRM_RM))
	/* 0xB4: LFS r?, m16:? */ INST(UNSUPPORTED())
	/* 0xB5: LGS r?, m16:? */ INST(UNSUPPORTED())
	/* 0xB6: MOVZX r?, r/m8 */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xB7: MOVZX r?, r/m16 */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xB8: ??? */ INST(UNKNOWN())
	/* 0xB9: ??? */ INST(UNKNOWN())
	/* GRP8: 4/BT, 5/BTS, 6/BTR, 7/BTC */
	/* 0xBA: [GRP8] r/m?, imm8 */ INST(MODRM(1), READ(MODRM_RM))
	/* 0xBB: BTC r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM))
	/* 0xBC: BSF r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xBD: BSR r?, r/m? */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xBE: MOVSX r?, r/m8 */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xBF: MOVSX r?, r/m16 */ INST(MODRM(0), READ(MODRM_RM), WRITE(MODRM_R))
	/* 0xC0: XADD r/m8, r8 */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0xC1: XADD r/m?, r? */ INST(MODRM(0), READ(MODRM_R | MODRM_RM), WRITE(MODRM_R | MODRM_RM))
	/* 0xC2: ??? */ INST(UNKNOWN())
	/* 0xC3: ??? */ INST(UNKNOWN())
	/* 0xC4: ??? */ INST(UNKNOWN())
	/* 0xC5: ??? */ INST(UNKNOWN())
	/* 0xC6: ??? */ INST(UNKNOWN())
	/* 0xC7:
	1: CMPXCHG8B m64/m128
	5: XSAVES mem; XSAVES64 mem */ INST(EXTENSION(9))
	/* NOTE: The read and write information of these are not very accurate */
	/* 0xC8: BSWAP ?AX/R8? */ INST(NOP(), READ(REG_AX | REG_R8), WRITE(REG_AX | REG_R8))
	/* 0xC9: BSWAP ?CX/R9? */ INST(NOP(), READ(REG_CX | REG_R9), WRITE(REG_CX | REG_R9))
	/* 0xCA: BSWAP ?DX/R10? */ INST(NOP(), READ(REG_DX | REG_R10), WRITE(REG_DX | REG_R10))
	/* 0xCB: BSWAP ?BX/R11? */ INST(NOP(), READ(REG_BX | REG_R11), WRITE(REG_BX | REG_R11))
	/* 0xCC: BSWAP ?SP/R12? */ INST(NOP(), READ(REG_SP | REG_R12), WRITE(REG_SP | REG_R12))
	/* 0xCD: BSWAP ?BP/R13? */ INST(NOP(), READ(REG_BP | REG_R13), WRITE(REG_BP | REG_R13))
	/* 0xCE: BSWAP ?SI/R14? */ INST(NOP(), READ(REG_SI | REG_R14), WRITE(REG_SI | REG_R14))
	/* 0xCF: BSWAP ?DI/R15? */ INST(NOP(), READ(REG_DI | REG_R15), WRITE(REG_DI | REG_R15))
	/* 0xD0: ??? */ INST(UNKNOWN())
	/* 0xD1: ??? */ INST(UNKNOWN())
	/* 0xD2: ??? */ INST(UNKNOWN())
	/* 0xD3: ??? */ INST(UNKNOWN())
	/* 0xD4: ??? */ INST(UNKNOWN())
	/* 0xD5: ??? */ INST(UNKNOWN())
	/* 0xD6: ??? */ INST(UNKNOWN())
	/* 0xD7: ??? */ INST(UNKNOWN())
	/* 0xD8: ??? */ INST(UNKNOWN())
	/* 0xD9: ??? */ INST(UNKNOWN())
	/* 0xDA: ??? */ INST(UNKNOWN())
	/* 0xDB: ??? */ INST(UNKNOWN())
	/* 0xDC: ??? */ INST(UNKNOWN())
	/* 0xDD: ??? */ INST(UNKNOWN())
	/* 0xDE: ??? */ INST(UNKNOWN())
	/* 0xDF: ??? */ INST(UNKNOWN())
	/* 0xE0: ??? */ INST(UNKNOWN())
	/* 0xE1: ??? */ INST(UNKNOWN())
	/* 0xE2: ??? */ INST(UNKNOWN())
	/* 0xE3: ??? */ INST(UNKNOWN())
	/* 0xE4: ??? */ INST(UNKNOWN())
	/* 0xE5: ??? */ INST(UNKNOWN())
	/* 0xE6: ??? */ INST(UNKNOWN())
	/* 0xE7: ??? */ INST(UNKNOWN())
	/* 0xE8: ??? */ INST(UNKNOWN())
	/* 0xE9: ??? */ INST(UNKNOWN())
	/* 0xEA: ??? */ INST(UNKNOWN())
	/* 0xEB: ??? */ INST(UNKNOWN())
	/* 0xEC: ??? */ INST(UNKNOWN())
	/* 0xED: ??? */ INST(UNKNOWN())
	/* 0xEE: ??? */ INST(UNKNOWN())
	/* 0xEF: ??? */ INST(UNKNOWN())
	/* 0xF0: ??? */ INST(UNKNOWN())
	/* 0xF1: ??? */ INST(UNKNOWN())
	/* 0xF2: ??? */ INST(UNKNOWN())
	/* 0xF3: ??? */ INST(UNKNOWN())
	/* 0xF4: ??? */ INST(UNKNOWN())
	/* 0xF5: ??? */ INST(UNKNOWN())
	/* 0xF6: ??? */ INST(UNKNOWN())
	/* 0xF7: ??? */ INST(UNKNOWN())
	/* 0xF8: ??? */ INST(UNKNOWN())
	/* 0xF9: ??? */ INST(UNKNOWN())
	/* 0xFA: ??? */ INST(UNKNOWN())
	/* 0xFB: ??? */ INST(UNKNOWN())
	/* 0xFC: ??? */ INST(UNKNOWN())
	/* 0xFD: ??? */ INST(UNKNOWN())
	/* 0xFE: ??? */ INST(UNKNOWN())
	/* 0xFF: ??? */ INST(UNKNOWN())
};
