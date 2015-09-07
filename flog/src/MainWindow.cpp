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
#include "MainWindow.h"

LRESULT MainWindow::OnCreate(LPCREATESTRUCT cs)
{
	m_processTree.Create(*this, rcDefault, NULL,
		WS_CHILD | WS_VISIBLE | WS_VSCROLL | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS,
		WS_EX_CLIENTEDGE);

	m_splitter.Create(*this, rcDefault, NULL, WS_CHILD | WS_VISIBLE);
	m_logViewerFont.CreateFontW(18, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
		OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_DONTCARE, L"Consolas");
	InitLogViewer(m_defaultLogViewer);
	m_defaultLogViewer.SetWindowTextW(L"No Foreign Linux client connected.");

	m_splitter.SetSplitterPanes(m_processTree, m_defaultLogViewer);

	m_hWndClient = m_splitter;
	UpdateLayout();

	m_splitter.SetSplitterPos(240);
	m_splitter.SetSplitterExtendedStyle(0);
	m_splitter.m_bFullDrag = FALSE;

	m_logServer.Start(*this);
	return 0;
}

void MainWindow::OnClose()
{
	DestroyWindow();
}

void MainWindow::OnDestroy()
{
	PostQuitMessage(0);
}

LRESULT MainWindow::OnNewClient(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled)
{
	uint32_t pid = (uint32_t)wParam;
	uint32_t tid = (uint32_t)lParam;
	/* Find the place to insert item */
	WCHAR text[256];
	wsprintfW(text, L"PID: %d, TID: %d\n", pid, tid);
	int parentId = -1;
	HTREEITEM item = NULL;
	for (int i = (int)m_clients.size() - 1; i >= 0; i--)
	{
		Client *parent = m_clients[i].front().get();
		if (parent->pid == pid)
		{
			Client *after = m_clients[i].back().get();
			item = m_processTree.InsertItem(TVIF_TEXT, text, 0, 0, TVIS_BOLD, TVIS_BOLD, 0, parent->item, after->item);
			parentId = i;
			break;
		}
	}
	if (!item)
	{
		item = m_processTree.InsertItem(TVIF_TEXT, text, 0, 0, TVIS_BOLD, TVIS_BOLD, 0, NULL, NULL);
		m_clients.emplace_back();
		parentId = (int)m_clients.size() - 1;
	}
	std::unique_ptr<Client> client = std::make_unique<Client>();
	client->pid = pid;
	client->tid = tid;
	client->item = item;
	m_processTree.SetItemData(client->item, (DWORD_PTR)client.get());
	InitLogViewer(client->logViewer);
	if (m_splitter.GetSplitterPane(SPLIT_PANE_RIGHT) == m_defaultLogViewer)
		SetCurrentLogViewer(client->logViewer);
	m_clients[parentId].push_back(std::move(client));
	m_processTree.Invalidate();
	return 0;
}

LRESULT MainWindow::OnLogReceive(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled)
{
	bHandled = TRUE;
	LogMessage *msg = (LogMessage *)wParam;
	for (int i = (int)m_clients.size() - 1; i >= 0; i--)
		if (m_clients[i].front()->pid == msg->pid)
			for (auto & client : m_clients[i])
				if (client->tid == msg->tid)
				{
					std::string &msgpart = client->msgpart;
					const char *buffer = msg->buffer;
					int length = msg->length;
					/* For each message packet */
					for (;;)
					{
						/* Append message size */
						while (msgpart.size() < 4 && length > 0)
						{
							msgpart += *buffer++;
							length--;
						}
						/* No enough data for size field for now */
						if (msgpart.size() < 4)
							break;
						size_t size = *(int32_t*)msgpart.c_str();
						/* Copy data */
						while (msgpart.size() < size && length > 0)
						{
							msgpart += *buffer++;
							length--;
						}
						/* No enough data for now */
						if (msgpart.size() < size)
							break;
						/* We got enough data, process it */
						ProcessClientLog(client.get(), (LogPacket *)msgpart.c_str());
						/* Clear current message buffer */
						msgpart.clear();
					}
				}
	return 0;
}

LRESULT MainWindow::OnTreeItemChange(LPNMHDR pnmh)
{
	NMTVITEMCHANGE *notification = (NMTVITEMCHANGE *)pnmh;
	HTREEITEM hItem = notification->hItem;
	if (notification->uStateNew & TVIS_SELECTED)
	{
		Client *client = (Client *)m_processTree.GetItemData(hItem);
		SetCurrentLogViewer(client->logViewer);
		m_processTree.SetItemState(hItem, 0, TVIS_BOLD);
	}
	return 0;
}

void MainWindow::ProcessClientLog(Client *client, LogPacket *packet)
{
	WCHAR *wbuffer = (WCHAR*)alloca(sizeof(WCHAR) * (packet->packetSize + 1));
	int len = MultiByteToWideChar(CP_UTF8, 0, packet->text, packet->len, wbuffer, packet->packetSize);
	if (len)
	{
		wbuffer[len] = 0;
		client->logViewer.AddLine(packet->type, wbuffer);
		if (m_splitter.GetSplitterPane(SPLIT_PANE_RIGHT) != client->logViewer)
			m_processTree.SetItemState(client->item, TVIS_BOLD, TVIS_BOLD);
	}
}

void MainWindow::InitLogViewer(LogViewer &logViewer)
{
	logViewer.Create(m_splitter, rcDefault);
	logViewer.SetFont(m_logViewerFont);
}

void MainWindow::SetCurrentLogViewer(LogViewer &logViewer)
{
	HWND hOldPane = m_splitter.GetSplitterPane(SPLIT_PANE_RIGHT);
	if (hOldPane != logViewer)
	{
		CWindow oldViewer;
		oldViewer.Attach(hOldPane);
		oldViewer.ShowWindow(SW_HIDE);
		logViewer.ShowWindow(SW_SHOW);
		m_splitter.SetSplitterPane(SPLIT_PANE_RIGHT, logViewer);
	}
}
