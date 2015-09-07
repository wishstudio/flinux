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
	m_savedX = 0;
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
			GetTextExtentPoint32W(dc, m_lines[i].c_str(), start, &size);
			dc.ExtTextOutW(x, y, 0, NULL, m_lines[i].c_str(), start, 0);
			x += size.cx;
			/* Draw selection */
			dc.SetTextColor(RGB(0xFF, 0xFF, 0xFF));
			GetTextExtentPoint32W(dc, m_lines[i].c_str() + start, end - start, &size);
			dc.FillSolidRect(x, y, size.cx, FONT_SIZE, RGB(0x00, 0xAA, 0xFF));
			dc.ExtTextOutW(x, y, 0, NULL, m_lines[i].c_str() + start, end - start, 0);
			x += size.cx;
			/* Draw text after selection */
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

void LogViewer::OnSetFocus(CWindow wndOld)
{
	CreateSolidCaret(1, FONT_SIZE);
	UpdateCaret();
	ShowCaret();
}

void LogViewer::OnKillFocus(CWindow wndFocus)
{
	DestroyCaret();
}

void LogViewer::OnLButtonDown(UINT nFlags, CPoint point)
{
	SetFocus();
	m_mouseDown = true;
	if (nFlags & MK_SHIFT)
		m_selEnd = TranslateMousePoint(point);
	else
		m_selStart = m_selEnd = TranslateMousePoint(point);
	Invalidate();
	SetCapture();
	UpdateCaret();
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
		m_selEnd = TranslateMousePoint(point);
		Invalidate();
		UpdateCaret();
	}
}

void LogViewer::OnRButtonDown(UINT nFlags, CPoint point)
{
	SetFocus();
}

void LogViewer::OnMButtonDown(UINT nFlags, CPoint point)
{
	SetFocus();
}

void LogViewer::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags)
{
	if (m_lines.empty())
		return;
	bool shift = (GetKeyState(VK_SHIFT) & 0x8000) > 0;
	bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) > 0;
	int pageSize = m_sizeClient.cy / FONT_SIZE;
	switch (nChar)
	{
	case VK_UP:
		if (m_selEnd.first > 0)
		{
			CPoint point = TranslateCharPosToClientPoint(m_selEnd);
			m_savedX = max(m_savedX, point.x);
			int y = (m_selEnd.first - 1) * FONT_SIZE;
			m_selEnd = TranslateClientPointToCharPos(CPoint(m_savedX, y));
		}
		if (!shift)
			m_selStart = m_selEnd;
		break;

	case VK_DOWN:
		if (m_selEnd.first + 1 < (int)m_lines.size())
		{
			CPoint point = TranslateCharPosToClientPoint(m_selEnd);
			m_savedX = max(m_savedX, point.x);
			int y = (m_selEnd.first + 1) * FONT_SIZE;
			m_selEnd = TranslateClientPointToCharPos(CPoint(m_savedX, y));
		}
		if (!shift)
			m_selStart = m_selEnd;
		break;

	case VK_PRIOR: /* Page up */
		if (m_selEnd.first > 0)
		{
			CPoint point = TranslateCharPosToClientPoint(m_selEnd);
			m_savedX = max(m_savedX, point.x);
			int y = max(0, m_selEnd.first - pageSize) * FONT_SIZE;
			m_selEnd = TranslateClientPointToCharPos(CPoint(m_savedX, y));
		}
		if (!shift)
			m_selStart = m_selEnd;
		break;

	case VK_NEXT: /* Page down */
		if (m_selEnd.first < (int)m_lines.size())
		{
			CPoint point = TranslateCharPosToClientPoint(m_selEnd);
			m_savedX = max(m_savedX, point.x);
			int y = min((int)m_lines.size() - 1, m_selEnd.first + pageSize) * FONT_SIZE;
			m_selEnd = TranslateClientPointToCharPos(CPoint(m_savedX, y));
		}
		if (!shift)
			m_selStart = m_selEnd;
		break;

	case VK_LEFT:
		if (m_selEnd.second == 0 && m_selEnd.first > 0)
		{
			m_selEnd.first--;
			m_selEnd.second = (int)m_lines[m_selEnd.first].size();
		}
		else if (m_selEnd.second > 0)
			m_selEnd.second--;
		if (!shift)
			m_selStart = m_selEnd;
		m_savedX = 0;
		break;

	case VK_RIGHT:
		if (m_selEnd.second == (int)m_lines[m_selEnd.first].size() && m_selEnd.first < (int)m_lines.size())
		{
			m_selEnd.first++;
			m_selEnd.second = 0;
		}
		else if (m_selEnd.second < (int)m_lines[m_selEnd.first].size())
			m_selEnd.second++;
		if (!shift)
			m_selStart = m_selEnd;
		m_savedX = 0;
		break;

	case VK_HOME:
		m_selEnd.second = 0;
		if (!shift)
			m_selStart = m_selEnd;
		m_savedX = 0;
		break;

	case VK_END:
		m_selEnd.second = (int)m_lines[m_selEnd.first].size();
		if (!shift)
			m_selStart = m_selEnd;
		m_savedX = 0;
		break;

	case 'A':
		if (ctrl)
		{
			m_selStart = std::make_pair(0, 0);
			m_selEnd = std::make_pair((int)m_lines.size() - 1, (int)m_lines.back().size());
			m_savedX = 0;
		}
		break;

	case 'C':
		if (ctrl)
			CopySelectionToClipboard();
		break;

	default:
		return;
	}
	Invalidate();
	UpdateCaret();
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

std::pair<int, int> LogViewer::TranslateMousePoint(CPoint mousePoint)
{
	if (m_lines.empty())
		return std::make_pair(0, 0);

	POINT offset;
	GetScrollOffset(offset);

	mousePoint.x += offset.x;
	mousePoint.y += offset.y;

	return TranslateClientPointToCharPos(mousePoint);
}

std::pair<int, int> LogViewer::TranslateClientPointToCharPos(CPoint clientPoint)
{
	int y = clientPoint.y / FONT_SIZE;
	if (y < 0)
		y = 0;
	if (y >= (int)m_lines.size())
		y = (int)m_lines.size() - 1;
	CDCHandle dc = GetDC();
	dc.SelectFont(m_font);
	int x = (int)m_lines[y].size();
	float cur = 0;
	for (int i = 0; i < (int)m_lines[y].size();)
	{
		if (clientPoint.x <= cur)
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
	return std::make_pair(y, x);
}

CPoint LogViewer::TranslateCharPosToClientPoint(std::pair<int, int> pos)
{
	CDCHandle dc = GetDC();
	dc.SelectFont(m_font);
	SIZE size;
	GetTextExtentPoint32W(dc, m_lines[pos.first].c_str(), pos.second, &size);
	ReleaseDC(dc);
	return CPoint(size.cx, pos.first * FONT_SIZE);
}

void LogViewer::UpdateCaret()
{
	int y = m_selEnd.first * FONT_SIZE;
	int x = 0;
	if (!m_lines.empty())
	{
		SIZE size;
		CDCHandle dc = GetDC();
		dc.SelectFont(m_font);
		GetTextExtentPoint32W(dc, m_lines[m_selEnd.first].c_str(), m_selEnd.second, &size);
		x = size.cx;
		ReleaseDC(dc);
	}
	RECT caret;
	caret.left = caret.right = x;
	caret.top = y;
	caret.bottom = y + FONT_SIZE;
	ScrollToView(caret);
	POINT offset;
	GetScrollOffset(offset);
	SetCaretPos(x - offset.x, y - offset.y);
	ShowCaret();
}

void LogViewer::CopySelectionToClipboard()
{
	/* Do we have anything to copy? */
	if (m_selStart == m_selEnd)
		return;
	/* Prepare data */
	std::wstring data;
	std::pair<int, int> start, end;
	start = min(m_selStart, m_selEnd);
	end = max(m_selStart, m_selEnd);
	/* First line */
	data += m_lines[start.first].substr(start.second);
	/* Middle lines */
	for (int i = start.first + 1; i < end.first; i++)
	{
		data += L"\r\n";
		data += m_lines[i];
	}
	/* Last line */
	data += L"\r\n";
	data += m_lines[end.first].substr(0, end.second);
	/* Copy data to clipboard */
	if (!OpenClipboard())
		return;
	if (!EmptyClipboard())
	{
		CloseClipboard();
		return;
	}
	HANDLE memory = GlobalAlloc(GMEM_MOVEABLE, (data.size() + 1) * sizeof(wchar_t));
	if (memory == NULL)
	{
		CloseClipboard();
		return;
	}
	void *buf = GlobalLock(memory);
	memcpy(buf, data.c_str(), (data.size() + 1) * sizeof(wchar_t));
	GlobalUnlock(memory);

	SetClipboardData(CF_UNICODETEXT, memory);
	CloseClipboard();
}
