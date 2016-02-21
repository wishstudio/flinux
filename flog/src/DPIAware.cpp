/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2015, 2016 Xiangyan Sun <wishstudio@gmail.com>
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

#include "DPIAware.h"

void DPIAware::Init(HWND hWnd)
{
	HDC hdc = GetDC(hWnd);
	m_dpix = GetDeviceCaps(hdc, LOGPIXELSX);
	m_dpiy = GetDeviceCaps(hdc, LOGPIXELSY);
	ReleaseDC(hWnd, hdc);
}

int DPIAware::GetPhysicalX(int logicalX)
{
	return MulDiv(logicalX, m_dpix, 96);
}

int DPIAware::GetPhysicalY(int logicalY)
{
	return MulDiv(logicalY, m_dpiy, 96);
}
