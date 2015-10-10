#pragma once

#define WIN32_NO_STATUS
#include <windef.h>
#include <ntstatus.h>

typedef LONG NTSTATUS;

#define STATUS_SUCCESS					0x00000000
#define STATUS_OBJECT_NAME_EXISTS		0x40000000
#define STATUS_NO_MORE_FILES			0x80000006
#define STATUS_CONFLICTING_ADDRESSES	0xC0000018
#define STATUS_NOT_MAPPED_VIEW			0xC0000019
#define STATUS_ACCESS_DENIED			0xC0000022
#define STATUS_OBJECT_NAME_COLLISION	0xC0000035
#define STATUS_SHARING_VIOLATION		0xC0000043

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

#define InitializeObjectAttributes( \
	_InitializedAttributes, \
	_ObjectName, \
	_Attributes, \
	_RootDirectory, \
	_SecurityDescriptor) \
	do \
	{ \
		(_InitializedAttributes)->Length = sizeof(OBJECT_ATTRIBUTES); \
		(_InitializedAttributes)->RootDirectory = _RootDirectory; \
		(_InitializedAttributes)->Attributes = _Attributes; \
		(_InitializedAttributes)->ObjectName = _ObjectName; \
		(_InitializedAttributes)->SecurityDescriptor = _SecurityDescriptor; \
		(_InitializedAttributes)->SecurityQualityOfService = NULL; \
	} while (0)

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

NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(
	_In_		HANDLE SourceProcessHandle,
	_In_		HANDLE SourceHandle,
	_In_opt_	HANDLE TargetProcessHandle,
	_Out_opt_	PHANDLE TargetHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_		ULONG HandleAttributes,
	_In_		ULONG Options
	);

NTSYSAPI NTSTATUS NTAPI NtClose(
	_In_		HANDLE ObjectHandle
	);

/* System information */
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG TimeZoneId;
	ULONG Reserved;
	ULONGLONG BootTimeBias;
	ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER Reserved1[2];
	ULONG Reserved2;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(
	_In_		SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_		PVOID SystemInformation,
	_In_		ULONG SystemInformationLength,
	_Out_opt_	PULONG ReturnLength
	);

/* Event objects */
typedef enum _EVENT_TYPE {
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE;

NTSYSAPI NTSTATUS NTAPI NtCreateEvent(
	_Out_		PHANDLE EventHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
	_In_		EVENT_TYPE EventType,
	_In_		BOOLEAN InitialState
	);

NTSYSAPI NTSTATUS NTAPI NtSetEvent(
	_In_		HANDLE EventHandle,
	_Out_opt_	PULONG PreviousState
	);

NTSYSAPI NTSTATUS NTAPI NtClearEvent(
	_In_		HANDLE EventHandle
	);

/* File API */
/* Create disposition flags */
#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

/* Create/open flags */
#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

NTSYSAPI NTSTATUS NTAPI NtCreateFile(
	_Out_		PHANDLE FileHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_		POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_		PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_	PLARGE_INTEGER AllocationSize,
	_In_		ULONG FileAttributes,
	_In_		ULONG ShareAccess,
	_In_		ULONG CreateDisposition,
	_In_		ULONG CreateOptions,
	_In_		PVOID EaBuffer,
	_In_		ULONG EaLength
	);

NTSYSAPI NTSTATUS NTAPI NtOpenFile(
	_Out_		PHANDLE FileHanle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_		POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_		PIO_STATUS_BLOCK IoStatusBlock,
	_In_		ULONG ShareAccess,
	_In_		ULONG OpenOptions
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

typedef struct _FILE_INTERNAL_INFORMATION {
	LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION {
	BOOLEAN ReplaceIfExists;
	HANDLE  RootDirectory;
	ULONG   FileNameLength;
	WCHAR   FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_LINK_INFORMATION {
	BOOLEAN ReplaceIfExists;
	HANDLE  RootDirectory;
	ULONG   FileNameLength;
	WCHAR   FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOL    DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION {
	LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

/* NamedPipeState */
#define FILE_PIPE_DISCONNECTED_STATE	0x00000001
#define FILE_PIPE_LISTENING_STATE		0x00000002
#define FILE_PIPE_CONNECTED_STATE		0x00000003
#define FILE_PIPE_CLOSING_STATE			0x00000004
typedef struct _FILE_PIPE_LOCAL_INFORMATION {
	ULONG NamedPipeType;
	ULONG NamedPipeConfiguration;
	ULONG MaximumInstances;
	ULONG CurrentInstances;
	ULONG InboundQuota;
	ULONG ReadDataAvailable;
	ULONG OutboundQuota;
	ULONG WriteQuotaAvailable;
	ULONG NamedPipeState;
	ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;

typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {
	ULONG FileAttributes;
	ULONG ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;

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

NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(
	_In_		HANDLE FileHandle,
	_Out_		PIO_STATUS_BLOCK IoStatusBlock,
	_Out_		PVOID FileInformation,
	_In_		ULONG Length,
	_In_		FILE_INFORMATION_CLASS FileInformationClass
	);

NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(
	_In_		HANDLE FileHandle,
	_Out_		PIO_STATUS_BLOCK IoStatusBlock,
	_In_		PVOID FileInformation,
	_In_		ULONG Length,
	_In_		FILE_INFORMATION_CLASS FileInformationClass
	);

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

/* FsInformation */
typedef enum _FS_INFORMATION_CLASS {
	FileFsVolumeInformation = 1,
	FileFsLabelInformation,
	FileFsSizeInformation,
	FileFsDeviceInformation,
	FileFsAttributeInformation,
	FileFsControlInformation,
	FileFsFullSizeInformation,
	FileFsObjectIdInformation,
	FileFsDriverPathInformation,
	FileFsVolumeFlagsInformation,
	FileFsSectorSizeInformation,
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef struct _FILE_FS_FULL_SIZE_INFORMATION {
	LARGE_INTEGER TotalAllocationUnits;
	LARGE_INTEGER CallerAvailableAllocationUnits;
	LARGE_INTEGER ActualAvailableAllocationUnits;
	ULONG         SectorsPerAllocationUnit;
	ULONG         BytesPerSector;
} FILE_FS_FULL_SIZE_INFORMATION, *PFILE_FS_FULL_SIZE_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(
	_In_		HANDLE FileHandle,
	_Out_		PIO_STATUS_BLOCK IoStatusBlock,
	_Out_		PVOID FsInformation,
	_In_		ULONG Length,
	_In_		FS_INFORMATION_CLASS FsInformationClass
	);

/* Extended attributes */
typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION {
	ULONG NextEntryOffset;
	UCHAR EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtQueryEaFile(
	_In_		HANDLE FileHandle,
	_Out_		PIO_STATUS_BLOCK IoStatusBlock,
	_Out_		PVOID Buffer,
	_In_		ULONG Length,
	_In_		BOOLEAN ReturnSingleEntry,
	_In_opt_	PVOID EaList,
	_In_		ULONG EaListLength,
	_In_opt_	PULONG EaIndex,
	_In_		BOOLEAN RestartScan
	);

NTSYSAPI NTSTATUS NTAPI NtSetEaFile(
	_In_		HANDLE FileHandle,
	_Out_		PIO_STATUS_BLOCK IoStatusBlock,
	_In_		PVOID Buffer,
	_In_		ULONG Length
	);

/* Virtual memory */
NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(
	_In_		HANDLE ProcessHandle,
	_In_		PVOID BaseAddress,
	_In_		PVOID Buffer,
	_In_		SIZE_T NumberOfBytesToWrite,
	_Out_opt_	PSIZE_T NumberOfBytesWritten
	);

NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(
	_In_		HANDLE ProcessHandle,
	_Inout_		PVOID *BaseAddress,
	_Inout_		SIZE_T *NumberOfBytesToProtect,
	_In_		ULONG NewAccessProtection,
	_Out_		PULONG OldAccessProtection
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

/* Thread */
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef LONG KPRIORITY;

NTSYSAPI NTSTATUS NTAPI NtDelayExecution(
	_In_		BOOLEAN Alertable,
	_In_		PLARGE_INTEGER DelayInterval
	);

NTSYSAPI NTSTATUS NTAPI NtQueryTimerResolution(
	_Out_		PULONG MinimumResolution,
	_Out_		PULONG MaximumResolution,
	_Out_		PULONG ActualResolution
	);

typedef enum _NT_THREAD_INFORMATION_CLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
} NT_THREAD_INFORMATION_CLASS;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(
	_In_		HANDLE ThreadHandle,
	_In_		NT_THREAD_INFORMATION_CLASS ThreadInformationClass,
	_Inout_		PVOID ThreadInformation,
	_In_		ULONG ThreadInformationLength,
	_Out_opt_	PULONG ReturnLength
	);

/* Token */
NTSYSAPI NTSTATUS NTAPI NtOpenProcessToken(
	_In_		HANDLE ProcessHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_Out_		PHANDLE TokenHandle
	);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationToken(
	_In_		HANDLE TokenHandle,
	_In_		TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_		PVOID TokenInformation,
	_In_		ULONG TokenInformationLength,
	_Out_		PULONG ReturnLength
	);

/* RTL functions */
#define HASH_STRING_ALGORITHM_DEFAULT	0
#define HASH_STRING_ALGORITHM_X65599	1
#define HASH_STRING_ALGORITHM_INVALID	0xFFFFFFFF

NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeStringToString(
	_Inout_		PUNICODE_STRING Destination,
	_In_		PCUNICODE_STRING Source
	);

NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeToString(
	_Inout_		PUNICODE_STRING Destination,
	_In_opt_	PCWSTR Source
	);

NTSYSAPI NTSTATUS NTAPI RtlConvertSidToUnicodeString(
	_Out_		PUNICODE_STRING UnicodeString,
	_In_		PSID Sid,
	_In_		BOOLEAN AllocateDestinationString
	);

NTSYSAPI NTSTATUS NTAPI RtlHashUnicodeString(
	_In_		PUNICODE_STRING UnicodeString,
	_In_		BOOLEAN CaseInSensitive,
	_In_		ULONG HashAlgorithm,
	_Out_		PULONG HashValue
	);

NTSYSAPI void NTAPI RtlInitUnicodeString(
	_Out_		PUNICODE_STRING DestinationString,
	_In_opt_	PCWSTR SourceString
	);

NTSYSAPI NTSTATUS NTAPI RtlInt64ToUnicodeString(
	_In_		ULONGLONG Value,
	_In_opt_	ULONG Base,
	_Inout_		PUNICODE_STRING String
	);

NTSYSAPI NTSTATUS NTAPI RtlIntegerToUnicodeString(
	_In_		ULONG Value,
	_In_opt_	ULONG Base,
	_Inout_		PUNICODE_STRING String
	);

NTSYSAPI NTSTATUS NTAPI RtlInitAnsiString(
	_Out_		PANSI_STRING DestinationString,
	_In_opt_	PCSTR SourceString
	);

/* Helper routines */
/* Initialize an empty unicode string given buffer and size */
_inline void RtlInitEmptyUnicodeString(
	_Out_		PUNICODE_STRING DestinationString,
	_In_		PWCHAR Buffer,
	_In_		USHORT BufferSize
	)
{
	DestinationString->Length = 0;
	DestinationString->MaximumLength = BufferSize;
	DestinationString->Buffer = Buffer;
}

/* Initialize a string from a counted string */
_inline void RtlInitCountedUnicodeString(
	_Out_		PUNICODE_STRING DestinationString,
	_In_		PWCHAR String,
	_In_		USHORT StringSize
	)
{
	DestinationString->Length = DestinationString->MaximumLength = StringSize;
	DestinationString->Buffer = String;
}

/* Append a 64 bit integer to an unicode string */
_inline NTSTATUS RtlAppendInt64ToString(
	_In_		ULONGLONG Value,
	_In_opt_	ULONG Base,
	_Inout_		PUNICODE_STRING String
	)
{
	WCHAR buf[32];
	UNICODE_STRING str;
	RtlInitEmptyUnicodeString(&str, buf, sizeof(buf));
	RtlInt64ToUnicodeString(Value, Base, &str);
	return RtlAppendUnicodeStringToString(String, &str);
}

/* Append an integer to an unicode string */
_inline NTSTATUS RtlAppendIntegerToString(
	_In_		ULONG Value,
	_In_opt_	ULONG Base,
	_Inout_		PUNICODE_STRING String
	)
{
	WCHAR buf[32];
	UNICODE_STRING str;
	RtlInitEmptyUnicodeString(&str, buf, sizeof(buf));
	RtlIntegerToUnicodeString(Value, Base, &str);
	return RtlAppendUnicodeStringToString(String, &str);
}

/* Ldr Functions */
NTSYSAPI NTSTATUS NTAPI LdrLoadDll(
	_In_opt_	PWCHAR PathToFile,
	_In_		PWSTR Flags,
	_In_		PUNICODE_STRING ModuleFileName,
	_Out_		PHANDLE ModuleHandle
	);

NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(
	_In_		HANDLE ModuleHandle,
	_In_opt_	PANSI_STRING FunctionName,
	_In_		WORD Ordinal,
	_Out_		PVOID *FunctionAddress
	);
