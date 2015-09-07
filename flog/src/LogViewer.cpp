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

constexpr int FONT_SIZE = 18;

HWND LogViewer::Create(HWND hWndParent, ATL::_U_RECT rect, LPCTSTR szWindowName)
{
	HWND hWnd = CWindowImpl<LogViewer>::Create(hWndParent, rect, szWindowName,
		WS_CHILD | WS_VISIBLE | WS_VSCROLL,
		WS_EX_CLIENTEDGE);
	m_font.CreateFont(FONT_SIZE, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FF_DONTCARE, _T("Consolas"));
	m_timerShot = false;
	m_mouseDown = false;
	m_selStart = std::make_pair(0, 0);
	m_selEnd = std::make_pair(0, 0);
	SetScrollSize(1, 1, FALSE);
	return hWnd;
}

void LogViewer::DoPaint(CDCHandle dc)
{
	POINT offset;
	GetScrollOffset(offset);

	RECT clientRect;
	GetClientRect(&clientRect);
	/* Erase background */
	dc.FillRect(&clientRect, COLOR_WINDOW);

	std::pair<int, int> selStart, selEnd;
	selStart = min(m_selStart, m_selEnd);
	selEnd = max(m_selStart, m_selEnd);
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
		if (i < selStart.first || i > selEnd.first)
		{
			/* Draw ordinary line */
			dc.ExtTextOutW(0, y, 0, NULL, m_lines[i].c_str(), -1, 0);
		}
		else
		{
			/* Draw line with text selection */
			/* The range of selected characters in this line is [start, end) */
			int start, end;
			if (i == selStart.first)
				start = selStart.second;
			else
				start = 0;
			if (i == selEnd.first)
				end = selEnd.second;
			else
				end = m_lines[i].size();
			int x = 0;
			SIZE size;
			/* Draw text before selection */
			dc.ExtTextOutW(x, y, 0, NULL, m_lines[i].c_str(), start, 0);
			/* Calculate text metrics */
			GetTextExtentPoint32W(dc, m_lines[i].c_str(), start, &size);
			x += size.cx;
			/* Draw selection */
			dc.SetBkMode(OPAQUE);
			dc.SetBkColor(RGB(0, 0, 0xFF));
			dc.SetTextColor(RGB(0xFF, 0xFF, 0xFF));
			dc.ExtTextOutW(x, y, 0, NULL, m_lines[i].c_str() + start, end - start, 0);
			/* Calculate text metrics */
			GetTextExtentPoint32W(dc, m_lines[i].c_str() + start, end - start, &size);
			x += size.cx;
			/* Draw text after selection */
			dc.SetBkMode(TRANSPARENT);
			dc.SetTextColor(RGB(0, 0, 0));
			dc.ExtTextOutW(x, y, 0, NULL, m_lines[i].c_str() + end, -1, 0);
		}
	}
}

void LogViewer::OnTimer(UINT_PTR id)
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
}

void LogViewer::OnLButtonDown(UINT nFlags, CPoint point)
{
	CPoint pos = TranslateMousePoint(point);
	m_mouseDown = true;
	if (nFlags & MK_SHIFT)
		m_selEnd = std::make_pair(pos.y, pos.x);
	else
		m_selStart = m_selEnd = std::make_pair(pos.y, pos.x);
	Invalidate();
	SetCapture();
}

void LogViewer::OnLButtonUp(UINT nFlags, CPoint point)
{
	m_mouseDown = false;
	ReleaseCapture();
}

void LogViewer::OnMouseMove(UINT nFlags, CPoint point)
{
	if (m_mouseDown)
	{
		CPoint pos = TranslateMousePoint(point);
		m_selEnd = std::make_pair(pos.y, pos.x);
		Invalidate();
	}
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

CPoint LogViewer::TranslateMousePoint(CPoint mousePoint)
{
	if (m_lines.empty())
		return CPoint(0, 0);

	POINT offset;
	GetScrollOffset(offset);

	mousePoint.x += offset.x;
	mousePoint.y += offset.y;

	int y = mousePoint.y / FONT_SIZE;
	if (y >= (int)m_lines.size())
		y = (int)m_lines.size() - 1;
	CDCHandle dc = GetDC();
	dc.SelectFont(m_font);
	int x = (int)m_lines[y].size();
	float cur = 0;
	for (int i = 0; i < (int)m_lines[y].size();)
	{
		if (mousePoint.x <= cur)
		{
			x = i;
			break;
		}
		ABCFLOAT abc;
		UINT ch;
		/* UTF-16 surrogate pair handling */
		if (IS_HIGH_SURROGATE(m_lines[y][i]))
		{
			UINT high = m_lines[y][i] - 0xD800;
			UINT low = m_lines[y][i + 1] - 0xDC00;
			ch = (high << 10) + low + 0x10000;
			i += 2;
		}
		else
			ch = m_lines[y][i++];
		if (GetCharABCWidthsFloatW(dc, m_lines[y][i], m_lines[y][i], &abc))
			cur += abc.abcfA + abc.abcfB + abc.abcfC;
	}
	ReleaseDC(dc);
	return CPoint(x, y);
}
