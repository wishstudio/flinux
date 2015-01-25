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
	WCHAR text[256];
	wsprintfW(text, L"PID: %d\n", pid);
	HTREEITEM item = m_processTree.InsertItem(TVIF_TEXT, text, 0, 0, TVIS_BOLD, TVIS_BOLD, 0, NULL, NULL);
	m_processTree.SetItemData(item, (DWORD_PTR)pid);
	std::unique_ptr<Client> client = std::make_unique<Client>();
	client->pid = pid;
	client->item = item;
	InitLogViewer(client->logViewer);
	if (m_splitter.GetSplitterPane(SPLIT_PANE_RIGHT) == m_defaultLogViewer)
		SetCurrentLogViewer(client->logViewer);
	m_clients.push_back(std::move(client));
	return 0;
}

LRESULT MainWindow::OnLogReceive(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled)
{
	LogMessage *msg = (LogMessage *)wParam;
	WCHAR wbuffer[LOG_BUFFER_SIZE + 1];
	int r = MultiByteToWideChar(CP_UTF8, 0, msg->buffer, msg->length, wbuffer, LOG_BUFFER_SIZE + 1);
	if (r)
	{
		wbuffer[r] = 0;
		for (int i = 0; i < m_clients.size(); i++)
			if (m_clients[i]->pid == msg->pid)
			{
				m_clients[i]->logViewer.AppendText(wbuffer, TRUE, FALSE);
				if (m_splitter.GetSplitterPane(SPLIT_PANE_RIGHT) != m_clients[i]->logViewer)
					m_processTree.SetItemState(m_clients[i]->item, TVIS_BOLD, TVIS_BOLD);
			}
	}
	bHandled = TRUE;
	return 0;
}

LRESULT MainWindow::OnTreeItemChange(LPNMHDR pnmh)
{
	NMTVITEMCHANGE *notification = (NMTVITEMCHANGE *)pnmh;
	HTREEITEM hItem = notification->hItem;
	if (notification->uStateNew & TVIS_SELECTED)
	{
		uint32_t pid = (uint32_t)m_processTree.GetItemData(hItem);
		for (int i = 0; i < m_clients.size(); i++)
			if (m_clients[i]->pid == pid)
			{
				SetCurrentLogViewer(m_clients[i]->logViewer);
				m_processTree.SetItemState(hItem, 0, TVIS_BOLD);
			}
	}
	return 0;
}

void MainWindow::InitLogViewer(CEdit &logViewer)
{
	logViewer.Create(m_splitter, rcDefault, NULL,
		WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_WANTRETURN | ES_MULTILINE | ES_AUTOVSCROLL,
		WS_EX_CLIENTEDGE);
	logViewer.SetFont(m_logViewerFont);
	logViewer.SetLimitText(-1);
}

void MainWindow::SetCurrentLogViewer(CEdit &logViewer)
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
