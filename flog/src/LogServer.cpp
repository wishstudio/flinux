/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2015 Xiangyan Sun <wishstudio@gmail.com>
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

#include "pch.h"

#include "LogServer.h"

LogServer::~LogServer()
{
	Stop();
}

void LogServer::Start(HWND hMainWnd)
{
	m_hMainWnd = hMainWnd;
	m_worker = std::thread([=]() { RunWorker(); });
	m_started = true;
}

void LogServer::Stop()
{
	if (m_started)
	{
		PostQueuedCompletionStatus(m_hCompletionPort, 0, NULL, NULL);
		m_worker.join();
	}
}

void LogServer::AddClient()
{
	/* Create named pipe instance */
	std::unique_ptr<Client> client(new Client());
	client->hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\flog_server", PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
		PIPE_UNLIMITED_INSTANCES, 32, LOG_BUFFER_SIZE, 0, nullptr);
	memset(&client->overlapped, 0, sizeof(client->overlapped));

	/* Associate it with IOCP */
	client->op = OP_CONNECT;

	CreateIoCompletionPort(client->hPipe, m_hCompletionPort, (ULONG_PTR)client.get(), 0);
	if (!ConnectNamedPipe(client->hPipe, &client->overlapped) && GetLastError() == ERROR_PIPE_CONNECTED)
	{
		/* Post a connection notification */
		PostQueuedCompletionStatus(m_hCompletionPort, 0, (ULONG_PTR)client.get(), &client->overlapped);
	}
	m_clients.push_back(std::move(client));
}

void LogServer::RemoveClient(Client *client)
{
	CloseHandle(client->hPipe);
	for (auto i = m_clients.begin(); i != m_clients.end(); ++i)
		if (i->get() == client)
		{
			m_clients.erase(i);
			break;
		}
}

/* Communication sequence
 * Client              Server
 * Connect      ->
 * Request      ->
 *                  Disconnect if request version mismatches
 * (execution)
 * Log data     ->
 * (execution)
 * Disconnect
 */

#define PROTOCOL_VERSION	1
#define PROTOCOL_MAGIC		'flog'
struct Request
{
	uint32_t magic;
	uint32_t version;
	uint32_t pid;
	uint32_t tid;
};

void LogServer::RunWorker()
{
	m_hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 1);
	AddClient();

	for (;;)
	{
		DWORD bytes;
		ULONG_PTR key;
		LPOVERLAPPED overlapped;
		BOOL succeed = GetQueuedCompletionStatus(m_hCompletionPort, &bytes, &key, &overlapped, INFINITE);

		if (key == NULL)
			break;

		Client *client = (Client *)key;
		switch (client->op)
		{
		case OP_CONNECT:
		{
			if (!succeed)
				RemoveClient(client);
			else
			{
				client->op = OP_READ_REQUEST;
				ReadFile(client->hPipe, client->buffer, sizeof(Request), NULL, &client->overlapped);
			}
			AddClient();
			break;
		}

		case OP_READ_REQUEST:
		{
			if (!succeed)
				RemoveClient(client);
			else
			{
				Request *request = (Request *)client->buffer;
				if (request->magic != PROTOCOL_MAGIC || request->version != PROTOCOL_VERSION)
					RemoveClient(client); /* TODO: Error message */
				else
				{
					client->pid = request->pid;
					client->tid = request->tid;
					client->op = OP_READ;
					SendMessageW(m_hMainWnd, WM_NEWCLIENT, (WPARAM)client->pid, 0);
					ReadFile(client->hPipe, client->buffer, LOG_BUFFER_SIZE, NULL, &client->overlapped);
				}
			}
			break;
		}

		case OP_READ:
		{
			if (!succeed)
				RemoveClient(client);
			else
			{
				LogMessage msg;
				msg.pid = client->pid;
				msg.buffer = client->buffer;
				msg.length = bytes;
				SendMessageW(m_hMainWnd, WM_LOGRECEIVE, (WPARAM)&msg, 0);
				ReadFile(client->hPipe, client->buffer, LOG_BUFFER_SIZE, NULL, &client->overlapped);
			}
			break;
		}
		}
	}
	for (auto const &client : m_clients)
		CloseHandle(client->hPipe);
	CloseHandle(m_hCompletionPort);
}
