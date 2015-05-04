/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <dbt/cpuid.h>
#include <str.h>

#include <intrin.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/* Kernel definitions for x86 cpu features is located at:
 *   arch/x86/include/asm/cpufeature.h
 */

struct cpuinfo_feature
{
	uint32_t mask;
	const char *name;
};

#define BIT(x)	(1 << (x))

/* Feature flags */
/* EAX = 0x00000001, EDX */
#define FEATURE_FPU				BIT(0)	/* Onboard FPU */
#define FEATURE_VME				BIT(1)	/* Virtual Mode Extensions */
#define FEATURE_DE				BIT(2)	/* Debugging Extensions */
#define FEATURE_PSE				BIT(3)	/* Page Size Extensions */
#define FEATURE_TSC				BIT(4)	/* Time Stamp Counter */
#define FEATURE_MSR				BIT(5)	/* Model-Specific Registers */
#define FEATURE_PAE				BIT(6)	/* Physical Address Extensions */
#define FEATURE_MCE				BIT(7)	/* Machine Check Exception */
#define FEATURE_CX8				BIT(8)	/* CMPXCHG8 instruction */
#define FEATURE_APIC			BIT(9)	/* Onboard APIC */
#define FEATURE_SEP				BIT(11)	/* SYSENTER/SYSEXIT */
#define FEATURE_MTRR			BIT(12)	/* Memory Type Range Registers */
#define FEATURE_PGE				BIT(13)	/* Page Global Enable */
#define FEATURE_MCA				BIT(14)	/* Machine Check Architecture */
#define FEATURE_CMOV			BIT(15)	/* CMOV instructions (plus FCMOVcc, FCMOI with FPU) */
#define FEATURE_PAT				BIT(16)	/* Page Attribute Table */
#define FEATURE_PSE_36			BIT(17)	/* 36-bit PSEs */
#define FEATURE_PSN				BIT(18)	/* Processor serial number */
#define FEATURE_CLFSH			BIT(19)	/* CLFLUSH instruction */
#define FEATURE_DS				BIT(21)	/* Debug Store */
#define FEATURE_ACPI			BIT(22)	/* ACPI via MSR */
#define FEATURE_MMX				BIT(23)	/* Multimedia Extensions */
#define FEATURE_FXSR			BIT(24)	/* FXSAVE/FXRSTOR, CR4.OSFXSR */
#define FEATURE_SSE				BIT(25)	/* SSE */
#define FEATURE_SSE2			BIT(26)	/* SSE2 */
#define FEATURE_SS				BIT(27)	/* CPU Self Snoop*/
#define FEATURE_HTT				BIT(28)	/* Hyper-Threading */
#define FEATURE_TM				BIT(29)	/* Automatic clock control */
#define FEATURE_IA64			BIT(30)	/* IA64 processor */
#define FEATURE_PBE				BIT(31)	/* Pending Break Enable */
static struct cpuinfo_feature cpuinfo_features_00000001_edx[] =
{
	{ FEATURE_FPU, "fpu" },
	{ FEATURE_VME, "vme" },
	{ FEATURE_DE, "de" },
	{ FEATURE_PSE, "pse" },
	{ FEATURE_TSC, "tsc" },
	{ FEATURE_MSR, "msr" },
	{ FEATURE_PAE, "pae" },
	{ FEATURE_MCE, "mce" },
	{ FEATURE_CX8, "cx8" },
	{ FEATURE_APIC, "apic" },
	{ FEATURE_SEP, "sep" },
	{ FEATURE_MTRR, "mtrr" },
	{ FEATURE_PGE, "pge" },
	{ FEATURE_MCA, "mca" },
	{ FEATURE_CMOV, "cmov" },
	{ FEATURE_PAT, "pat" },
	{ FEATURE_PSE_36, "pse36" },
	{ FEATURE_PSN, "pn" },
	{ FEATURE_CLFSH, "clflush" },
	{ FEATURE_DS, "dts" },
	{ FEATURE_ACPI, "acpi" },
	{ FEATURE_MMX, "mmx" },
	{ FEATURE_FXSR, "fxsr" },
	{ FEATURE_SSE, "sse" },
	{ FEATURE_SSE2, "sse2" },
	{ FEATURE_SS, "ss" },
	{ FEATURE_HTT, "ht" },
	{ FEATURE_TM, "tm" },
	{ FEATURE_IA64, "ia64" },
	{ FEATURE_PBE, "pbe" },
};

/* EAX = 0x80000001, EDX */
#define FEATURE_SYSCALL			BIT(11) /* SYSCALL/SYSRET available in 64-bit mode */
#define FEATURE_NX				BIT(20) /* Execute disable bit */
#define FEATURE_MMXEXT			BIT(22)	/* AMD MMX Extensions */
#define FEATURE_FXSR_OPT		BIT(25)	/* FXSAVE/FXRSTOR optimizations */
#define FEATURE_GPAGE			BIT(26) /* 1G page */
#define FEATURE_RDTSCP			BIT(27) /* RDTSCP and IA32_TSC_AUX */
#define FEATURE_64				BIT(29) /* Long Mode (x86-64) */
#define FEATURE_3DNOWEXT		BIT(30)	/* AMD 3DNow! extensions */
#define FEATURE_3DNOW			BIT(31)	/* 3DNow! instructions */
static struct cpuinfo_feature cpuinfo_features_80000001_edx[] =
{
	{ FEATURE_SYSCALL, "syscall" },
	{ FEATURE_NX, "nx" },
	{ FEATURE_MMXEXT, "mmxext" },
	{ FEATURE_FXSR_OPT, "fxsr_opt" },
	{ FEATURE_GPAGE, "pdpe1gb" },
	{ FEATURE_RDTSCP, "rdtscp" },
	{ FEATURE_64, "lm" },
	{ FEATURE_3DNOWEXT, "3dnowext" },
	{ FEATURE_3DNOW, "3dnow" }
};

/* EAX = 0x00000001, ECX */
#define FEATURE_SSE3			BIT(0)	/* SSE3 instructions */
#define FEATURE_PCLMULQDQ		BIT(1)	/* PCLMULQDQ instruction */
#define FEATURE_DTES64			BIT(2)	/* 64-bit Debug Store */
#define FEATURE_MONITOR			BIT(3)	/* Monitor/Mwait Support */
#define FEATURE_DS_CPL			BIT(4)	/* CPL Qual. Debug Store */
#define FEATURE_VMX				BIT(5)	/* Hardware virtualization */
#define FEATURE_SMX				BIT(6)	/* Safer mode */
#define FEATURE_EST				BIT(7)	/* Enhanced SpeedStep */
#define FEATURE_TM2				BIT(8)	/* Thermal Monitor 2 */
#define FEATURE_SSSE3			BIT(9)	/* Supplemental SSE3 instructions */
#define FEATURE_CNXT_ID			BIT(10)	/* Context ID */
#define FEATURE_FMA				BIT(12)	/* Fused multiply-add instructions */
#define FEATURE_CMPXCHG16B		BIT(13)	/* CMPXCHG16B instruction */
#define FEATURE_XTPR			BIT(14)	/* Send Task Priority Messages */
#define FEATURE_PDCM			BIT(15)	/* Performance Capabilities */
#define FEATURE_PCID			BIT(17)	/* Process Context Identifiers */
#define FEATURE_DCA				BIT(18)	/* Direct Cache Access */
#define FEATURE_SSE41			BIT(19)	/* SSE4.1 instructions */
#define FEATURE_SSE42			BIT(20)	/* SSE4.2 instructions */
#define FEATURE_X2APIC			BIT(21)	/* x2APIC */
#define FEATURE_MOVBE			BIT(22)	/* MOVBE instruction */
#define FEATURE_POPCNT			BIT(23)	/* POPCNT instruction */
#define FEATURE_TSC_DEADLINE	BIT(24)	/* TSC deadline timer */
#define FEATURE_AES				BIT(25)	/* AES instructions */
#define FEATURE_XSAVE			BIT(26)	/* XSAVE/XRSTOR/XSETBV/XSETBV */
#define FEATURE_OSXSAVE			BIT(27)	/* XSAVE enabled in the OS */
#define FEATURE_AVX				BIT(28)	/* Advanced Vector Extensions */
#define FEATURE_F16C			BIT(29)	/* 16-bit fp conversions */
#define FEATURE_RDRAND			BIT(30)	/* RDRAND instruction */
#define FEATURE_HYPERVISOR		BIT(31)	/* Running on a hypervisor */
static struct cpuinfo_feature cpuinfo_features_00000001_ecx[] =
{
	{ FEATURE_SSE3, "pni" },
	{ FEATURE_PCLMULQDQ, "pclmulqdq" },
	{ FEATURE_DTES64, "dtes64" },
	{ FEATURE_MONITOR, "monitor" },
	{ FEATURE_DS_CPL, "ds_cpl" },
	{ FEATURE_VMX, "vmx" },
	{ FEATURE_SMX, "smx" },
	{ FEATURE_EST, "est" },
	{ FEATURE_TM2, "tm2" },
	{ FEATURE_SSSE3, "ssse3" },
	{ FEATURE_CNXT_ID, "cid" },
	{ FEATURE_FMA, "fma" },
	{ FEATURE_CMPXCHG16B, "cx16" },
	{ FEATURE_XTPR, "xtpr" },
	{ FEATURE_PDCM, "pdcm" },
	{ FEATURE_PCID, "pcid" },
	{ FEATURE_DCA, "dca" },
	{ FEATURE_SSE41, "sse4_1" },
	{ FEATURE_SSE42, "sse4_2" },
	{ FEATURE_X2APIC, "x2apic" },
	{ FEATURE_MOVBE, "movbe" },
	{ FEATURE_POPCNT, "popcnt" },
	{ FEATURE_TSC_DEADLINE, "tsc_deadline_timer" },
	{ FEATURE_AES, "aes" },
	{ FEATURE_XSAVE, "xsave" },
	//{ FEATURE_OSXSAVE, "osxsave" },
	{ FEATURE_AVX, "avx" },
	{ FEATURE_F16C, "f16c" },
	{ FEATURE_RDRAND, "rdrand" },
	{ FEATURE_HYPERVISOR, "hypervisor" },
};

/* EAX = 0x80000001, ECX (AMD extensions) */
#define FEATURE_LAHF			BIT(0)	/* LAHF/SAHF available in 64-bit mode */
#define FEATURE_CMP_LEGACY		BIT(1)	/* Core multi-processing legacy mode */
#define FEATURE_SVM				BIT(2)	/* Secure Virtual Machine */
#define FEATURE_EXTAPIC			BIT(3)	/* Extended APIC space */
#define FEATURE_CR8_LEGACY		BIT(4)	/* LOCK MOV CR0 means MOV CR8 */
#define FEATURE_ABM				BIT(5)	/* Advanced Bit Manipulation */
#define FEATURE_SSE4A			BIT(6)	/* SSE4A instructions */
#define FEATURE_MISALIGNSSE		BIT(7)	/* Misaligned SSE mode */
#define FEATURE_3DNOWPREFETCH	BIT(8)	/* PREFETCH and PREFETCHW instructions */
#define FEATURE_OSVW			BIT(9)	/* OS Visible Workaround */
#define FEATURE_IBS				BIT(10)	/* Instruction Based Sampling */
#define FEATURE_XOP				BIT(11)	/* Extended Operation Support */
#define FEATURE_SKINIT			BIT(12)	/* SKINIT and STGI instructions */
#define FEATURE_WDT				BIT(13)	/* Watchdog Timer */
#define FEATURE_LWP				BIT(15)	/* Lightweight Profiling Support */
#define FEATURE_FMA4			BIT(16)	/* 4-operand FMA instructions */
#define FEATURE_TCE				BIT(17)	/* Translation Cache Extension */
#define FEATURE_NODEID_MSR		BIT(19)	/* NodeID MSR */
#define FEATURE_TBM				BIT(21)	/* Trailing Bit Manipulation instructions */
#define FEATURE_TOPOEXT			BIT(22)	/* Topology extensions */
#define FEATURE_PERFCTR_CORE	BIT(23)	/* Core performance counter extensions */
#define FEATURE_PERFCTR_NB		BIT(24)	/* NB performance counter extensions */
#define FEATURE_BPEXT			BIT(26)	/* Data breakpoint extensions */
#define FEATURE_PERFCTR_L2		BIT(28)	/* L2 performance counter extensions */
static struct cpuinfo_feature cpuinfo_features_80000001_ecx[] =
{
	{ FEATURE_LAHF, "lahf_lm" },
	{ FEATURE_CMP_LEGACY, "cmp_legacy" },
	{ FEATURE_SVM, "svm" },
	{ FEATURE_EXTAPIC, "extapic" },
	{ FEATURE_CR8_LEGACY, "cr8_legacy" },
	{ FEATURE_ABM, "abm" },
	{ FEATURE_SSE4A, "sse4a" },
	{ FEATURE_MISALIGNSSE, "misalignsse" },
	{ FEATURE_3DNOWPREFETCH, "3dnowprefetch" },
	{ FEATURE_OSVW, "osvw" },
	{ FEATURE_IBS, "ibs" },
	{ FEATURE_XOP, "xop" },
	{ FEATURE_SKINIT, "skinit" },
	{ FEATURE_WDT, "wdt" },
	{ FEATURE_LWP, "lwp" },
	{ FEATURE_FMA4, "fma4" },
	{ FEATURE_TCE, "tce" },
	{ FEATURE_NODEID_MSR, "nodeid_msr" },
	{ FEATURE_TBM, "tbm" },
	{ FEATURE_TOPOEXT, "topoext" },
	{ FEATURE_PERFCTR_CORE, "perfctr_core" },
	{ FEATURE_PERFCTR_NB, "perfctr_nb" },
	{ FEATURE_BPEXT, "bpext" },
	{ FEATURE_PERFCTR_L2, "perfctr_l2" },
};

/* EAX = 7, Sub-leaf 0, EBX */
#define FEATURE_FSGSBASE		BIT(0)	/* Supports RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE */
#define FEATURE_TSC_ADJUST		BIT(1)	/* IA32_TSC_ADJUST MSR */
#define FEATURE_BMI1			BIT(3)	/* 1st group Bit Manipulation Extensions */
#define FEATURE_HLE				BIT(4)	/* Hardware Lock Elision */
#define FEATURE_AVX2			BIT(5)	/* AVX2 instructions */
#define FEATURE_SMEP			BIT(7)	/* Supervisor mode execution protection */
#define FEATURE_BMI2			BIT(8)	/* 2nd group Bit Manipulation Extensions */
#define FEATURE_ERMS			BIT(9)	/* Enhanced REP MOVSB/STOSB */
#define FEATURE_INVPCID			BIT(10)	/* INVPCID instruction */
#define FEATURE_RTM				BIT(11)	/* Restricted Transactional Memory */
#define FEATURE_MPX				BIT(14)	/* Memory Protection Extension */
#define FEATURE_AVX512F			BIT(16)	/* AVX-512 Foundation */
#define FEATURE_RDSEED			BIT(18)	/* RDSEED instruction */
#define FEATURE_ADX				BIT(19)	/* ADCX and ADOX instructions */
#define FEATURE_SMAP			BIT(20)	/* Supervisor Mode Access Prevention */
#define FEATURE_CLFLUSHOPT		BIT(23)	/* CLFLUSHOPT instruction */
#define FEATURE_AVX512PF		BIT(26)	/* AVX-512 Prefetch */
#define FEATURE_AVX512ER		BIT(27)	/* AVX-512 Exponential and Reciprocal */
#define FEATURE_AVX512CD		BIT(28)	/* AVX-512 Conflict Detection */
static struct cpuinfo_feature cpuinfo_features_7_0_ebx[] =
{
	{ FEATURE_FSGSBASE, "fsgsbase" },
	{ FEATURE_TSC_ADJUST, "tsc_adjust" },
	{ FEATURE_BMI1, "bmi1" },
	{ FEATURE_HLE, "hle" },
	{ FEATURE_AVX2, "avx2" },
	{ FEATURE_SMEP, "smep" },
	{ FEATURE_BMI2, "bmi2" },
	{ FEATURE_ERMS, "erms" },
	{ FEATURE_INVPCID, "invpcid" },
	{ FEATURE_RTM, "rtm" },
	{ FEATURE_MPX, "mpx" },
	{ FEATURE_AVX512F, "avx512f" },
	{ FEATURE_RDSEED, "rdseed" },
	{ FEATURE_ADX, "adx" },
	{ FEATURE_SMAP, "smap" },
	{ FEATURE_CLFLUSHOPT, "clflushopt" },
	{ FEATURE_AVX512PF, "avx512pf" },
	{ FEATURE_AVX512ER, "avx512er" },
	{ FEATURE_AVX512CD, "avx512cd" },
};

void dbt_cpuid(int eax, int ecx, struct cpuid_t *cpuid)
{
	int cpuinfo[4];
	__cpuidex(cpuinfo, eax, ecx);
	cpuid->eax = cpuinfo[0];
	cpuid->ebx = cpuinfo[1];
	cpuid->ecx = cpuinfo[2];
	cpuid->edx = cpuinfo[3];
	/* Mangle cpu feature bits, omit unsupported features  */
	if (eax == 0x01)
	{
		/* Feature information */
		cpuid->edx &= (0
			| FEATURE_FPU
			| FEATURE_VME
			| FEATURE_DE
			| FEATURE_PSE
			| FEATURE_TSC
			| FEATURE_MSR
			| FEATURE_PAE
			| FEATURE_MCE
			| FEATURE_CX8
			| FEATURE_APIC
			//| FEATURE_SEP
			| FEATURE_MTRR
			| FEATURE_PGE
			| FEATURE_MCA
			| FEATURE_CMOV
			| FEATURE_PAT
			| FEATURE_PSE_36
			| FEATURE_PSN
			| FEATURE_CLFSH
			| FEATURE_DS
			| FEATURE_ACPI
			| FEATURE_MMX
			| FEATURE_FXSR
			| FEATURE_SSE
			| FEATURE_SSE2
			| FEATURE_SS
			| FEATURE_HTT
			| FEATURE_TM
			| FEATURE_IA64
			| FEATURE_PBE
			);
		cpuid->ecx &= (0
			| FEATURE_SSE3
			//| FEATURE_PCLMULQDQ
			| FEATURE_DTES64
			| FEATURE_MONITOR
			| FEATURE_DS_CPL
			| FEATURE_VMX
			| FEATURE_SMX
			| FEATURE_EST
			| FEATURE_TM2
			| FEATURE_SSSE3
			| FEATURE_CNXT_ID
			//| FEATURE_FMA
			//| FEATURE_CMPXCHG16B
			| FEATURE_XTPR
			| FEATURE_PDCM
			| FEATURE_PCID
			| FEATURE_DCA
			| FEATURE_SSE41
			| FEATURE_SSE42
			| FEATURE_X2APIC
			| FEATURE_MOVBE
			| FEATURE_POPCNT
			| FEATURE_TSC_DEADLINE
			//| FEATURE_AES
			//| FEATURE_XSAVE
			//| FEATURE_OSXSAVE
			//| FEATURE_AVX
			//| FEATURE_F16C
			//| FEATURE_RDRAND
			| FEATURE_HYPERVISOR
			);
	}
	else if (eax == 0x80000001)
	{
		/* Extended function */
		cpuid->edx &= (0
			| FEATURE_SYSCALL
			| FEATURE_NX
			//| FEATURE_MMXEXT
			//| FEATURE_FXSR_OPT
			| FEATURE_GPAGE
			//| FEATURE_RDTSCP
			| FEATURE_64
			//| FEATURE_3DNOWEXT
			//| FEATURE_3DNOW
			);
		/* AMD extensions */
		cpuid->ecx &= (0
			| FEATURE_LAHF
			//| FEATURE_CMP_LEGACY
			//| FEATURE_SVM
			//| FEATURE_EXTAPIC
			//| FEATURE_CR8_LEGACY
			//| FEATURE_ABM
			//| FEATURE_SSE4A
			//| FEATURE_MISALIGNSSE
			//| FEATURE_3DNOWPREFETCH
			//| FEATURE_OSVW
			//| FEATURE_IBS
			//| FEATURE_XOP
			//| FEATURE_SKINIT
			//| FEATURE_WDT
			//| FEATURE_LWP
			//| FEATURE_FMA4
			//| FEATURE_TCE
			//| FEATURE_NODEID_MSR
			//| FEATURE_TBM
			//| FEATURE_TOPOEXT
			//| FEATURE_PERFCTR_CORE
			//| FEATURE_PERFCTR_NB
			//| FEATURE_BPEXT
			//| FEATURE_PERFCTR_L2
			);
	}
	else if (eax == 0x07)
	{
		/* Structured extended feature flags */
		if (ecx == 0x00)
		{
			cpuid->eax = 0;
			cpuid->ebx &= (0
				//| FEATURE_FSGSBASE
				| FEATURE_TSC_ADJUST
				//| FEATURE_BMI1
				//| FEATURE_HLE
				//| FEATURE_AVX2
				| FEATURE_SMEP
				//| FEATURE_BMI2
				| FEATURE_ERMS
				//| FEATURE_INVPCID
				//| FEATURE_RTM
				//| FEATURE_MPX
				//| FEATURE_AVX512F
				//| FEATURE_RDSEED
				//| FEATURE_ADX
				//| FEATURE_SMAP
				//| FEATURE_CLFLUSHOPT
				//| FEATURE_AVX512PF
				//| FEATURE_AVX512ER
				//| FEATURE_AVX512CD
				);
			cpuid->ecx = 0;
			cpuid->edx = 0;
		}
		else
			cpuid->eax = cpuid->ebx = cpuid->ecx = cpuid->edx = 0;
	}
}

int dbt_get_cpuinfo(char *buf)
{
	char *buf_original = buf;

	struct cpuid_t cpuid_00000001, cpuid_80000001;
	dbt_cpuid(0x00000001, 0, &cpuid_00000001);
	dbt_cpuid(0x80000001, 0, &cpuid_80000001);
	for (int i = 0; i < ARRAYSIZE(cpuinfo_features_00000001_edx); i++)
		if (cpuid_00000001.edx & cpuinfo_features_00000001_edx[i].mask)
			buf += ksprintf(buf, " %s", cpuinfo_features_00000001_edx[i].name);

	for (int i = 0; i < ARRAYSIZE(cpuinfo_features_80000001_edx); i++)
		if (cpuid_80000001.edx & cpuinfo_features_80000001_edx[i].mask)
			buf += ksprintf(buf, " %s", cpuinfo_features_80000001_edx[i].name);

	for (int i = 0; i < ARRAYSIZE(cpuinfo_features_00000001_ecx); i++)
		if (cpuid_00000001.ecx & cpuinfo_features_00000001_ecx[i].mask)
			buf += ksprintf(buf, " %s", cpuinfo_features_00000001_ecx[i].name);

	for (int i = 0; i < ARRAYSIZE(cpuinfo_features_80000001_ecx); i++)
		if (cpuid_80000001.ecx & cpuinfo_features_80000001_ecx[i].mask)
			buf += ksprintf(buf, " %s", cpuinfo_features_80000001_ecx[i].name);

	struct cpuid_t cpuid_7_0;
	dbt_cpuid(7, 0, &cpuid_7_0);
	for (int i = 0; i < ARRAYSIZE(cpuinfo_features_7_0_ebx); i++)
		if (cpuid_7_0.ebx & cpuinfo_features_7_0_ebx[i].mask)
			buf += ksprintf(buf, " %s", cpuinfo_features_7_0_ebx[i].name);
	
	return buf - buf_original;
}
