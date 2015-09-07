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
		MSG_WM_SETFOCUS(OnSetFocus)
		MSG_WM_KILLFOCUS(OnKillFocus)
		MSG_WM_LBUTTONDOWN(OnLButtonDown)
		MSG_WM_LBUTTONUP(OnLButtonUp)
		MSG_WM_MOUSEMOVE(OnMouseMove)
		MSG_WM_RBUTTONDOWN(OnRButtonDown)
		MSG_WM_MBUTTONDOWN(OnMButtonDown)
		MSG_WM_KEYDOWN(OnKeyDown)
		CHAIN_MSG_MAP(CDoubleBufferImpl<LogViewer>)
		CHAIN_MSG_MAP(CScrollImpl<LogViewer>)
	END_MSG_MAP()

	HWND Create(HWND hWndParent, ATL::_U_RECT rect = NULL, LPCTSTR szWindowName = NULL);
	void DoPaint(CDCHandle dc);
	void OnTimer(UINT_PTR id);
	void OnSetFocus(CWindow wndOld);
	void OnKillFocus(CWindow wndFocus);
	void OnLButtonDown(UINT nFlags, CPoint point);
	void OnLButtonUp(UINT nFlags, CPoint point);
	void OnMouseMove(UINT nFlags, CPoint point);
	void OnRButtonDown(UINT nFlags, CPoint point);
	void OnMButtonDown(UINT nFlags, CPoint point);
	void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
	void AddLine(int type, const std::wstring &msg);

private:
	std::pair<int, int> TranslateMousePoint(CPoint mousePoint);
	std::pair<int, int> TranslateClientPointToCharPos(CPoint clientPoint);
	CPoint TranslateCharPosToClientPoint(std::pair<int, int> pos);
	void UpdateCaret(bool scrollToCaret = true);
	void CopySelectionToClipboard();

	CFont m_font;
	bool m_timerShot, m_mouseDown;
	std::pair<int, int> m_selStart, m_selEnd;
	int m_savedX;
	std::vector<int> m_types;
	std::vector<std::wstring> m_lines;
};
