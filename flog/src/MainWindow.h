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

#include "LogServer.h"
#include "LogViewer.h"

class MainWindow: public CFrameWindowImpl<MainWindow>
{
public:
	BEGIN_MSG_MAP(MainWindow)
		MSG_WM_CREATE(OnCreate)
		MSG_WM_CLOSE(OnClose)
		MSG_WM_DESTROY(OnDestroy)
		MESSAGE_HANDLER(WM_NEWCLIENT, OnNewClient)
		MESSAGE_HANDLER(WM_LOGRECEIVE, OnLogReceive)
		NOTIFY_CODE_HANDLER_EX(TVN_ITEMCHANGED, OnTreeItemChange)
		CHAIN_MSG_MAP(CFrameWindowImpl<MainWindow>)
	END_MSG_MAP()

	LRESULT OnCreate(LPCREATESTRUCTW cs);
	void OnClose();
	void OnDestroy();
	LRESULT OnNewClient(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled);
	LRESULT OnLogReceive(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled);
	LRESULT OnTreeItemChange(LPNMHDR pnmh);
	
private:
	void InitLogViewer(LogViewer &logViewer);
	void SetCurrentLogViewer(LogViewer &logViewer);

	LogServer m_logServer;
	CSplitterWindow m_splitter;
	CTreeViewCtrl m_processTree;
	CFont m_logViewerFont;
	LogViewer m_defaultLogViewer;
	struct Client
	{
		uint32_t pid;
		uint32_t tid;
		HTREEITEM item;
		LogViewer logViewer;
	};
	std::vector<std::vector<std::unique_ptr<Client>>> m_clients;
};
