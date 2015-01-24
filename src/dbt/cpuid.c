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

#include <intrin.h>

#define BIT(x)	(1 << (x))

/* Feature flags */
/* EAX = 1, ECX */
#define FEATURE_SSE3			BIT(0)
#define FEATURE_PCLMULQDQ		BIT(1)
#define FEATURE_DTES64			BIT(2)
#define FEATURE_MONITOR			BIT(3)
#define FEATURE_DS_CPL			BIT(4)
#define FEATURE_VMX				BIT(5)
#define FEATURE_SMX				BIT(6)
#define FEATURE_EST				BIT(7)
#define FEATURE_TM2				BIT(8)
#define FEATURE_SSSE3			BIT(9)
#define FEATURE_CNXT_ID			BIT(10)
#define FEATURE_FMA				BIT(12)
#define FEATURE_CMPXCHG16B		BIT(13)
#define FEATURE_XTPR			BIT(14)
#define FEATURE_PDCM			BIT(15)
#define FEATURE_PCID			BIT(17)
#define FEATURE_DCA				BIT(18)
#define FEATURE_SSE41			BIT(19)
#define FEATURE_SSE42			BIT(20)
#define FEATURE_X2APIC			BIT(21)
#define FEATURE_MOVBE			BIT(22)
#define FEATURE_POPCNT			BIT(23)
#define FEATURE_TSC_DEADLINE	BIT(24)
#define FEATURE_AES				BIT(25)
#define FEATURE_XSAVE			BIT(26)
#define FEATURE_OSXSAVE			BIT(27)
#define FEATURE_AVX				BIT(28)
#define FEATURE_F16C			BIT(29)
#define FEATURE_RDRAND			BIT(30)

/* EAX = 1, EDX */
#define FEATURE_FPU				BIT(0)
#define FEATURE_VME				BIT(1)
#define FEATURE_DE				BIT(2)
#define FEATURE_PSE				BIT(3)
#define FEATURE_TSC				BIT(4)
#define FEATURE_MSR				BIT(5)
#define FEATURE_PAE				BIT(6)
#define FEATURE_MCE				BIT(7)
#define FEATURE_CX8				BIT(8)
#define FEATURE_APIC			BIT(9)
#define FEATURE_SEP				BIT(11)
#define FEATURE_MTRR			BIT(12)
#define FEATURE_PGE				BIT(13)
#define FEATURE_MCA				BIT(14)
#define FEATURE_CMOV			BIT(15)
#define FEATURE_PAT				BIT(16)
#define FEATURE_PSE_36			BIT(17)
#define FEATURE_PSN				BIT(18)
#define FEATURE_CLFSH			BIT(19)
#define FEATURE_DS				BIT(21)
#define FEATURE_ACPI			BIT(22)
#define FEATURE_MMX				BIT(23)
#define FEATURE_FXSR			BIT(24)
#define FEATURE_SSE				BIT(25)
#define FEATURE_SSE2			BIT(26)
#define FEATURE_SS				BIT(27)
#define FEATURE_HTT				BIT(28)
#define FEATURE_TM				BIT(29)
#define FEATURE_PBE				BIT(31)

/* EAX = 7, Sub-leaf 0, EBX */
#define FEATURE_FSGSBASE		BIT(0) /* Supports RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE */
#define FEATURE_TSC_ADJUST		BIT(1) /* IA32_TSC_ADJUST MSR */
#define FEATURE_SMEP			BIT(7) /* Supervisor mode execution protection */
#define FEATURE_ERMS			BIT(9) /* Enhanced REP MOVSB/STOSB */
#define FEATURE_INVPCID			BIT(10) /* INVPCID instruction */
#define FEATURE_QM				BIT(12) /* Quality of service monitoring */
#define FEATURE_DEP_FPU_CSDS	BIT(13) /* Deprecates FPU CS and FPU DS values */

/* EAX = 0x80000001, ECX */
#define FEATURE_LAHF			BIT(0) /* LAHF/SAHF available in 64-bit mode */

/* EAX = 0x80000001, EDX */
#define FEATURE_SYSCALL			BIT(11) /* SYSCALL/SYSRET available in 64-bit mode */
#define FEATURE_NX				BIT(20) /* Execute disable bit */
#define FEATURE_GPAGE			BIT(26) /* 1G page */
#define FEATURE_RDTSCP			BIT(27) /* RDTSCP and IA32_TSC_AUX */
#define FEATURE_64				BIT(29) /* 64 bit */

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
			);
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
			| FEATURE_PBE
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
				| FEATURE_SMEP
				| FEATURE_ERMS
				//| FEATURE_INVPCID
				| FEATURE_QM
				| FEATURE_DEP_FPU_CSDS
				);
			cpuid->ecx = 0;
			cpuid->edx = 0;
		}
		else
			cpuid->eax = cpuid->ebx = cpuid->ecx = cpuid->edx = 0;
	}
	else if (eax == 0x80000001)
	{
		/* Extended function */
		cpuid->ecx &= (0
			| FEATURE_LAHF
			);
		cpuid->edx &= (0
			| FEATURE_SYSCALL
			| FEATURE_NX
			| FEATURE_GPAGE
			//| FEATURE_RDTSCP
			| FEATURE_64
			);
	}
}
