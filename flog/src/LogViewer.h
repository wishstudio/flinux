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

class LogViewer: public CWindowImpl<LogViewer>, public CScrollImpl<LogViewer>, public CDoubleBufferImpl<LogViewer>
{
public:
	static ATL::CWndClassInfo& GetWndClassInfo()
	{
		static ATL::CWndClassInfo wc =
		{
			{
				sizeof(WNDCLASSEX), CS_DBLCLKS, StartWindowProc,
				0, 0, NULL, NULL, NULL, (HBRUSH)(COLOR_WINDOW + 1), NULL, _T("FLOG_LogViewer"), NULL
			},
			NULL, NULL, IDC_IBEAM, TRUE, 0, _T("")
		};
		return wc;
	}

	BEGIN_MSG_MAP(LogViewer)
		MSG_WM_TIMER(OnTimer)
		CHAIN_MSG_MAP(CDoubleBufferImpl<LogViewer>)
		CHAIN_MSG_MAP(CScrollImpl<LogViewer>)
	END_MSG_MAP()

	HWND Create(HWND hWndParent, ATL::_U_RECT rect = NULL, LPCTSTR szWindowName = NULL);
	LRESULT DoPaint(CDCHandle dc);
	HRESULT OnTimer(UINT_PTR id);
	void AddLine(const std::wstring &line);

private:
	CFont m_font;
	bool m_timerShot;
	std::vector<std::wstring> m_lines;
	std::wstring m_lastLine;
};
