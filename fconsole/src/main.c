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
 * Console control pipe: (message mode), need acquiring control mutex first
 */
/* TODO: Replace control pipe with NT LPC */

#define BUF_SIZE		4096
#define MAX_READ_LEN	1024

static CRITICAL_SECTION input_buf_cs;
/* The pending input buffer is a ring buffer */
static char input_buf[BUF_SIZE];
static int input_buf_head, input_buf_tail;

static HANDLE data_event;
static HANDLE data_pipe_recv;
static OVERLAPPED data_pipe_recv_overlapped;
static char data_pipe_recv_buf[BUF_SIZE];

static HANDLE control_pipe_server;
static OVERLAPPED control_pipe_recv_overlapped, control_pipe_send_overlapped;
static char control_pipe_buf[BUF_SIZE];
static void message_loop()
{
	HANDLE iocp = CreateIoCompletionPort(data_pipe_recv, NULL, 0, 1);
	CreateIoCompletionPort(control_pipe_server, iocp, 0, 1);
	memset(&data_pipe_recv_overlapped, 0, sizeof(data_pipe_recv_overlapped));
	memset(&control_pipe_recv_overlapped, 0, sizeof(control_pipe_recv_overlapped));
	memset(&control_pipe_send_overlapped, 0, sizeof(control_pipe_send_overlapped));
	ReadFile(data_pipe_recv, data_pipe_recv_buf, BUF_SIZE, NULL, &data_pipe_recv_overlapped);
	ReadFile(control_pipe_server, control_pipe_buf, BUF_SIZE, NULL, &control_pipe_recv_overlapped);
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
		else if (overlapped == &control_pipe_recv_overlapped)
		{
			/* Control message received */
			struct console_control_packet
			{
				uint32_t cmd;
				char data[0];
			};
			struct console_control_packet *packet = (struct console_control_packet *)control_pipe_buf;
			int size;
			if (packet->cmd == 0) /* Read request */
			{
				int len = *(int*)packet->data;
				len = min(len, MAX_READ_LEN);
				int read_count = 0;
				EnterCriticalSection(&input_buf_cs);
				if (input_buf_head < input_buf_tail)
				{
					int l = min(len, BUF_SIZE - input_buf_tail);
					memcpy(packet->data, input_buf + input_buf_tail, l);
					read_count += l;
					len -= l;
					input_buf_tail = (input_buf_tail + l) % BUF_SIZE;
				}
				if (len > 0)
				{
					int l = min(len, input_buf_head - input_buf_tail);
					memcpy(packet->data + read_count, input_buf + input_buf_tail, l);
					read_count += l;
					len -= l;
					input_buf_tail += l;
				}
				packet->cmd = read_count;
				size = sizeof(struct console_control_packet) + read_count;
				if (input_buf_head == input_buf_tail)
					ResetEvent(data_event);
				LeaveCriticalSection(&input_buf_cs);
				/* Send data back to client */
				WriteFile(control_pipe_server, control_pipe_buf, size, NULL, &control_pipe_send_overlapped);
			}
			else
			{
				size = console_control(packet->cmd, packet->data);
				/* Send response message */
				if (size > 0)
				{
					/* Data message */
					WriteFile(control_pipe_server, packet->data, size, NULL, &control_pipe_send_overlapped);
				}
				else
				{
					/* A single random byte to indicate successful */
					control_pipe_buf[0] = 0;
					WriteFile(control_pipe_server, control_pipe_buf, 1, NULL, &control_pipe_send_overlapped);
				}
			}
		}
		else if (overlapped == &control_pipe_send_overlapped)
		{
			/* Control response message sent, retrieve new control message */
			ReadFile(control_pipe_server, control_pipe_buf, BUF_SIZE, NULL, &control_pipe_recv_overlapped);
		}
	}
	CloseHandle(iocp);
}

static DWORD WINAPI console_thread(LPVOID lpParameter)
{
	HANDLE console_poll_handle = get_console_poll_handle();
	while (console_has_unread_input() || WaitForSingleObject(console_poll_handle, INFINITE) == WAIT_OBJECT_0)
	{
		EnterCriticalSection(&input_buf_cs);
		DWORD count;
		if (input_buf_head < input_buf_tail)
			count = (DWORD)console_read(input_buf + input_buf_head, input_buf_tail - input_buf_head);
		else
			count = (DWORD)console_read(input_buf + input_buf_head, BUF_SIZE - input_buf_head);
		input_buf_head = (input_buf_head + count) % BUF_SIZE;
		if (input_buf_head != input_buf_tail)
			SetEvent(data_event);
		LeaveCriticalSection(&input_buf_cs);
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

	ksprintf(pipe_name, "\\\\.\\pipe\\fconsole-control-%d", GetCurrentProcessId());
	control_pipe_server = CreateNamedPipeA(pipe_name,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		BUF_SIZE,
		BUF_SIZE,
		0,
		NULL);

	ksprintf(pipe_name, "fconsole-data-event-%d", GetCurrentProcessId());
	data_event = CreateEventA(NULL, TRUE, FALSE, pipe_name);

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
	
	InitializeCriticalSection(&input_buf_cs);
	input_buf_head = 0;
	input_buf_tail = 0;
	CreateThread(NULL, 0, console_thread, NULL, 0, NULL);
	message_loop();

out:
	CloseHandle(info.hProcess);
	CloseHandle(info.hThread);
	ExitProcess(0);
}
