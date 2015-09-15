#include "console.h"

#include <stdbool.h>
#include <stdint.h>

#pragma comment(linker,"/entry:main")
/* VS 2015 does not pull this in when manually specifying entrypoint, don't know why. */
#ifdef _DEBUG
#pragma comment(lib,"libucrtd")
#else
#pragma comment(lib,"libucrt")
#pragma comment(lib,"libvcruntime")
#endif

/* Console objects (shared between processes)
 * Console write pipe: write directly
 * Console read pipe: read directly
 * Console control pipe: (message mode), need acquiring control mutex first
 */

#define BUF_SIZE	4096

static bool create_console_thread_pipe(HANDLE *read, HANDLE *write)
{
	char pipe_name[256];
	ksprintf(pipe_name, "\\\\.\\pipe\\fconsole-%d", GetCurrentProcessId());
	HANDLE server = CreateNamedPipeA(pipe_name,
		PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		BUF_SIZE,
		BUF_SIZE,
		0,
		NULL);
	if (server == INVALID_HANDLE_VALUE)
		return false;
	DWORD desired_access = GENERIC_WRITE;
	HANDLE client = CreateFileA(pipe_name, desired_access, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (client == INVALID_HANDLE_VALUE)
	{
		CloseHandle(server);
		return false;
	}
	if (!ConnectNamedPipe(server, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
	{
		CloseHandle(server);
		CloseHandle(client);
	}
	*read = server;
	*write = client;
	return true;
}

static HANDLE data_pipe_recv;
static OVERLAPPED data_pipe_recv_overlapped;
static char data_pipe_recv_buf[BUF_SIZE];

static HANDLE console_thread_recv, console_thread_send;
static OVERLAPPED console_thread_recv_overlapped;
static HANDLE data_pipe_send;
static OVERLAPPED data_pipe_send_overlapped;
static char data_pipe_send_buf[BUF_SIZE];

static HANDLE control_pipe_server;
static OVERLAPPED control_pipe_recv_overlapped, control_pipe_send_overlapped;
static char control_pipe_recv_buf[BUF_SIZE];
static void message_loop()
{
	HANDLE iocp = CreateIoCompletionPort(data_pipe_recv, NULL, 0, 1);
	CreateIoCompletionPort(data_pipe_send, iocp, 0, 1);
	CreateIoCompletionPort(console_thread_recv, iocp, 0, 1);
	CreateIoCompletionPort(control_pipe_server, iocp, 0, 1);
	memset(&data_pipe_recv_overlapped, 0, sizeof(data_pipe_recv_overlapped));
	memset(&console_thread_recv_overlapped, 0, sizeof(console_thread_recv_overlapped));
	memset(&data_pipe_send_overlapped, 0, sizeof(data_pipe_send_overlapped));
	memset(&control_pipe_recv_overlapped, 0, sizeof(control_pipe_recv_overlapped));
	memset(&control_pipe_send_overlapped, 0, sizeof(control_pipe_send_overlapped));
	ReadFile(data_pipe_recv, data_pipe_recv_buf, BUF_SIZE, NULL, &data_pipe_recv_overlapped);
	ReadFile(console_thread_recv, data_pipe_send_buf, BUF_SIZE, NULL, &console_thread_recv_overlapped);
	ReadFile(control_pipe_server, control_pipe_recv_buf, BUF_SIZE, NULL, &control_pipe_recv_overlapped);
	for (;;)
	{
		DWORD bytes;
		ULONG_PTR key;
		LPOVERLAPPED overlapped;
		BOOL succeed = GetQueuedCompletionStatus(iocp, &bytes, &key, &overlapped, INFINITE);
		if (!succeed)
			break;
		if (overlapped == &data_pipe_recv_overlapped)
		{
			/* Data received, print out it */
			console_write(data_pipe_recv_buf, bytes);
			ReadFile(data_pipe_recv, data_pipe_recv_buf, BUF_SIZE, NULL, &data_pipe_recv_overlapped);
		}
		else if (overlapped == &console_thread_recv_overlapped)
		{
			/* Console input received, send it to client */
			WriteFile(data_pipe_send, data_pipe_send_buf, bytes, NULL, &data_pipe_send_overlapped);
		}
		else if (overlapped == &data_pipe_send_overlapped)
		{
			/* Console input send done, reread console input */
			ReadFile(console_thread_recv, data_pipe_send_buf, BUF_SIZE, NULL, &console_thread_recv_overlapped);
		}
		else if (overlapped == &control_pipe_recv_overlapped)
		{
			/* Control message received */
			struct console_control_packet
			{
				uint32_t cmd;
				char data[0];
			};
			struct console_control_packet *packet = (struct console_control_packet *)control_pipe_recv_buf;
			int size = console_control(packet->cmd, packet->data);
			/* Send response message */
			if (size > 0)
			{
				/* Data message */
				WriteFile(control_pipe_server, control_pipe_recv_buf, size, NULL, &control_pipe_send_overlapped);
			}
			else
			{
				/* A single random byte to indicate successful */
				control_pipe_recv_buf[0] = 0;
				WriteFile(control_pipe_server, control_pipe_recv_buf, 1, NULL, &control_pipe_send_overlapped);
			}
		}
		else if (overlapped == &control_pipe_send_overlapped)
		{
			/* Control response message sent, retrieve new control message */
			ReadFile(control_pipe_server, control_pipe_recv_buf, BUF_SIZE, NULL, &control_pipe_recv_overlapped);
		}
	}
	CloseHandle(iocp);
}

static DWORD WINAPI console_thread(LPVOID lpParameter)
{
	HANDLE console_poll_handle = get_console_poll_handle();
	char buf[BUF_SIZE];
	while (console_has_unread_input() || WaitForSingleObject(console_poll_handle, INFINITE) == WAIT_OBJECT_0)
	{
		DWORD count = (DWORD)console_read(buf, BUF_SIZE);
		DWORD start = 0;
		DWORD written;
		while (start < count)
		{
			WriteFile(console_thread_send, buf + start, count, &written, NULL);
			start += written;
		}
	}
	return 0;
}

void main()
{
	console_init();

	char pipe_name[256];
	ksprintf(pipe_name, "\\\\.\\pipe\\fconsole-write-%d", GetCurrentProcessId());
	data_pipe_recv = CreateNamedPipeA(pipe_name,
		PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		0,
		BUF_SIZE,
		0,
		NULL);

	ksprintf(pipe_name, "\\\\.\\pipe\\fconsole-read-%d", GetCurrentProcessId());
	data_pipe_send = CreateNamedPipeA(pipe_name,
		PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		BUF_SIZE,
		0,
		0,
		NULL);

	ksprintf(pipe_name, "\\\\.\\pipe\\fconsole-control-%d", GetCurrentProcessId());
	control_pipe_server = CreateNamedPipeA(pipe_name,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		BUF_SIZE,
		BUF_SIZE,
		0,
		NULL);

	LPWSTR cmdline = GetCommandLineW();
	wchar_t path[65536];
	int len = (int)GetModuleFileNameW(NULL, path, sizeof(path) - 1);
	while (path[len - 1] != '/' && path[len - 1] != '\\')
		len--;
	path[len++] = 'f';
	path[len++] = 'l';
	path[len++] = 'i';
	path[len++] = 'n';
	path[len++] = 'u';
	path[len++] = 'x';
	path[len++] = '.';
	path[len++] = 'e';
	path[len++] = 'x';
	path[len++] = 'e';
	path[len] = 0;

	// FIXME: First argument of cmdline is actually incorrect.
	STARTUPINFOW startup_info;
	memset(&startup_info, 0, sizeof(startup_info));
	startup_info.cb = sizeof(startup_info);
	PROCESS_INFORMATION info;
	if (!CreateProcessW(path, cmdline, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &startup_info, &info))
		goto out;

	if (!ConnectNamedPipe(data_pipe_recv, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
		goto out;
	if (!ConnectNamedPipe(control_pipe_server, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
		goto out;
	
	create_console_thread_pipe(&console_thread_recv, &console_thread_send);
	CreateThread(NULL, 0, console_thread, NULL, 0, NULL);
	message_loop();

out:
	CloseHandle(info.hProcess);
	CloseHandle(info.hThread);
	ExitProcess(0);
}
