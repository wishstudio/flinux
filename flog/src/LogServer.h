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

#pragma once

#define LOG_BUFFER_SIZE	65536

#define WM_NEWCLIENT	WM_USER + 1
#define WM_LOGRECEIVE	WM_USER + 2

struct LogMessage
{
	uint32_t pid;
	int length;
	char *buffer;
};

class LogServer
{
public:
	~LogServer();

	void Start(HWND hMainWnd);
	void Stop();

private:
	enum ClientOp
	{
		OP_CONNECT,
		OP_READ_REQUEST,
		OP_READ,
	};
	struct Client
	{
		HANDLE hPipe;
		ClientOp op;
		uint32_t pid, tid;
		OVERLAPPED overlapped;
		char buffer[LOG_BUFFER_SIZE];
	};

	void AddClient();
	void RemoveClient(Client *client);
	void RunWorker();

	std::thread m_worker;
	bool m_started;
	HWND m_hMainWnd;
	HANDLE m_hCompletionPort;
	std::vector<std::unique_ptr<Client>> m_clients;
};
