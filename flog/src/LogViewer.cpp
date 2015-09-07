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
#include "LogViewer.h"

const int FONT_SIZE = 18;

HWND LogViewer::Create(HWND hWndParent, ATL::_U_RECT rect, LPCTSTR szWindowName)
{
	HWND hWnd = CWindowImpl<LogViewer>::Create(hWndParent, rect, szWindowName,
		WS_CHILD | WS_VISIBLE | WS_VSCROLL,
		WS_EX_CLIENTEDGE);
	m_font.CreateFont(FONT_SIZE, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FF_DONTCARE, _T("Consolas"));
	m_timerShot = false;
	SetScrollSize(1, 1, FALSE);
	return hWnd;
}

LRESULT LogViewer::DoPaint(CDCHandle dc)
{
	POINT offset;
	GetScrollOffset(offset);

	RECT clientRect;
	GetClientRect(&clientRect);
	/* Erase background */
	dc.FillRect(&clientRect, COLOR_WINDOW);

	dc.SelectFont(m_font);
	dc.SetBkMode(TRANSPARENT);
	for (int i = offset.y / FONT_SIZE; i < (int)m_lines.size(); i++)
	{
		int y = clientRect.top + i * FONT_SIZE - offset.y;
		if (y > clientRect.bottom)
			break;
		RECT rect = clientRect;
		rect.top = y;
		rect.bottom = y + FONT_SIZE;
		if (m_types[i] == LOG_DEBUG)
			dc.FillSolidRect(&rect, RGB(0xE0, 0xF0, 0xFF));
		if (m_types[i] == LOG_WARNING)
			dc.FillSolidRect(&rect, RGB(0xFF, 0xDD, 0x44));
		if (m_types[i] == LOG_ERROR)
			dc.FillSolidRect(&rect, RGB(0xFF, 0x88, 0x88));
		dc.DrawText(m_lines[i].c_str(), -1, &rect, 0);
	}
	return 0;
}

HRESULT LogViewer::OnTimer(UINT_PTR id)
{
	POINT offset;
	GetScrollOffset(offset);
	bool atBottom = false;
	if (offset.y >= m_sizeAll.cy - m_sizeClient.cy - 1)
		atBottom = true;
	SetScrollSize(1, m_lines.size() * FONT_SIZE, TRUE, FALSE);
	if (atBottom)
	{
		offset.y = m_sizeAll.cy - m_sizeClient.cy;
		SetScrollOffset(offset);
	}
	KillTimer(id);
	m_timerShot = false;
	return 0;
}

void LogViewer::AddLine(int type, const std::wstring &line)
{
	m_types.push_back(type);
	m_lines.push_back(line);
	if (!m_timerShot)
	{
		SetTimer(1, 33); /* 30 FPS is enough */
		m_timerShot = true;
	}
}
