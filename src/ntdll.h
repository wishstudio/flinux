#pragma once

#include <windef.h>
#include <ntstatus.h>

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef NT_INFORMATION
#define NT_INFORMATION(Status) ((((ULONG)(Status)) >> 30) == 1)
#endif

#ifndef NT_WARNING
#define NT_WARNING(Status) ((((ULONG)(Status)) >> 30) == 2)
#endif

#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif

typedef CONST char *PCSZ;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID(NTAPI *PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);

#define NtCurrentProcess()	((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()	((HANDLE)(LONG_PTR)-2)

/* Object management */
#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_VALID_ATTRIBUTES    0x000001F2L

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG       Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG       HandleCount;
	ULONG       PointerCount;
	ULONG       Reserved[10];
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtQueryObject(
	_In_opt_	HANDLE Handle,
	_In_		OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_opt_	PVOID ObjectInformation,
	_In_		ULONG ObjectInformationLength,
	_Out_opt_	PULONG ReturnLength
	);

NTSYSAPI NTSTATUS NTAPI NtClose(
	_In_		HANDLE ObjectHandle
	);

/* File information class */
typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileAttributeCacheInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileReplaceCompletionInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtQueryDirectoryFile(
	_In_		HANDLE FileHandle,
	_In_opt_	HANDLE Event,
	_In_opt_	PIO_APC_ROUTINE ApcRoutine,
	_In_opt_	PVOID AppContext,
	_Out_		PIO_STATUS_BLOCK IoStatusBlock,
	_Out_		PVOID FileInformation,
	_In_		ULONG Length,
	_In_		FILE_INFORMATION_CLASS FileInformationClass,
	_In_		BOOLEAN ReturnSingleEntry,
	_In_opt_	PUNICODE_STRING FileName,
	_In_		BOOLEAN RestartScan
	);

/* Section object */
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

NTSYSAPI NTSTATUS NTAPI NtCreateSection(
	_Out_		PHANDLE SectionHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_	PLARGE_INTEGER MaximumSize,
	_In_		ULONG SectionPageProtection,
	_In_		ULONG AllocationAttributes,
	_In_opt_	HANDLE FileHandle
	);

NTSYSAPI NTSTATUS NTAPI NtOpenSection(
	_Out_		PHANDLE SectionHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_		POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(
	_In_		HANDLE SectionHandle,
	_In_		HANDLE ProcessHandle,
	_Inout_		PVOID *BaseAddress,
	_In_		ULONG_PTR ZeroBits,
	_In_		SIZE_T CommitSize,
	_Inout_opt_	PLARGE_INTEGER SectionOffset,
	_Inout_		PSIZE_T ViewSize,
	_In_		SECTION_INHERIT InheritDisposition,
	_In_		ULONG AllocationType,
	_In_		ULONG Win32Protect
	);

NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(
	_In_		HANDLE ProcessHandle,
	_In_opt_	PVOID BaseAddress
	);
