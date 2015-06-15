/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
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

#include <common/errno.h>
#include <common/fcntl.h>
#include <common/soundcard.h>
#include <fs/dsp.h>
#include <fs/file.h>
#include <syscall/mm.h>
#include <heap.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <mmreg.h>
#include <mmsystem.h>

#pragma comment(lib, "winmm.lib")

#define DSP_BUFFER_SIZE		65536

struct dsp_file
{
	struct virtualfs_custom custom_file;
	HWAVEOUT waveout;
	WAVEFORMATEX format;
	WAVEHDR hdr;
	char *buffer;
	HANDLE event;
};

static void dsp_reset(struct dsp_file *dsp)
{
	if (dsp->waveout)
	{
		waveOutUnprepareHeader(dsp->waveout, &dsp->hdr, sizeof(dsp->hdr));
		waveOutClose(dsp->waveout);
		dsp->waveout = NULL;
	}
	dsp->format.wFormatTag = WAVE_FORMAT_PCM;
	dsp->format.nChannels = 1;
	dsp->format.nSamplesPerSec = 8000;
	dsp->format.wBitsPerSample = 8;
	dsp->format.cbSize = 0;
}

static int dsp_close(struct file *f)
{
	struct dsp_file *dsp = (struct dsp_file *)f;
	dsp_reset(dsp);
	VirtualFree(dsp->buffer, DSP_BUFFER_SIZE, MEM_RELEASE);
	CloseHandle(dsp->event);
	kfree(dsp, sizeof(struct dsp_file));
	return 0;
}

static int dsp_read(struct file *f, void *buf, size_t count)
{
	/* TODO */
	log_error("/dev/dsp read not supported.\n");
	return 0;
}

static int dsp_write(struct file *f, const void *buf, size_t count)
{
	struct dsp_file *dsp = (struct dsp_file *)f;
	if (dsp->waveout == NULL)
	{
		dsp->format.nBlockAlign = dsp->format.nChannels * dsp->format.wBitsPerSample / 8;
		dsp->format.nAvgBytesPerSec = dsp->format.nSamplesPerSec * dsp->format.nBlockAlign;
		int r = waveOutOpen(&dsp->waveout, 0, &dsp->format, (DWORD_PTR)dsp->event, 0, CALLBACK_EVENT);
		if (r != MMSYSERR_NOERROR)
		{
			dsp->waveout = NULL;
			log_error("waveOutOpen() failed, error code: %d\n", r);
			return 0;
		}
		dsp->hdr.lpData = dsp->buffer;
		dsp->hdr.dwBufferLength = DSP_BUFFER_SIZE;
		dsp->hdr.dwBytesRecorded = 0;
		dsp->hdr.dwUser = 0;
		dsp->hdr.dwFlags = 0;
		dsp->hdr.dwLoops = 0;
		dsp->hdr.lpNext = NULL;
		dsp->hdr.reserved = 0;
		r = waveOutPrepareHeader(dsp->waveout, &dsp->hdr, sizeof(dsp->hdr));
		if (r != MMSYSERR_NOERROR)
		{
			waveOutClose(dsp->waveout);
			log_error("waveOutPrepareHeader() failed, error code: %d\n", r);
			return 0;
		}
	}
	if (count > DSP_BUFFER_SIZE)
		count = DSP_BUFFER_SIZE;
	memcpy(dsp->buffer, buf, count);
	/* TODO: Implement asychronous operation */
	int r = waveOutWrite(dsp->waveout, &dsp->hdr, sizeof(dsp->hdr));
	WaitForSingleObject(dsp->event, INFINITE);
	if (r == MMSYSERR_NOERROR)
		return count;
	else
	{
		log_error("waveOutWrite() failed, error code: %d\n", r);
		return 0;
	}
}

static int dsp_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	/* TODO: Check parameter validity (using WAVE_FORMAT_QUERY) */
	struct dsp_file *dsp = (struct dsp_file *)f;
	switch (cmd)
	{
	case SNDCTL_DSP_RESET:
	{
		log_info("SNDCTL_DSP_RESET.\n");
		dsp_reset(dsp);
		break;
	}
	case SNDCTL_DSP_SPEED:
	{
		if (!mm_check_read((int *)arg, sizeof(int)))
			return -EFAULT;
		int speed = *(int *)arg;
		log_info("SNDCTL_DSP_SPEED: %d\n", speed);
		dsp->format.nSamplesPerSec = speed;
		break;
	}
	case SNDCTL_DSP_STEREO:
	{
		if (!mm_check_read((int *)arg, sizeof(int)))
			return -EFAULT;
		int c = *(int *)arg;
		log_info("SNDCTL_DSP_STEREO: %d\n", c);
		if (c == 0)
			dsp->format.nChannels = 1;
		else if (c == 1)
			dsp->format.nChannels = 2;
		else
		{
			log_warning("Invalid argument (can only be 0 or 1).\n");
			return -EINVAL;
		}
		break;
	}
	case SNDCTL_DSP_SETFMT:
	{
		if (!mm_check_read((int *)arg, sizeof(int)))
			return -EFAULT;
		int fmt = *(int *)arg;
		log_info("SNDCTL_DSP_SETFMT: 0x%x\n", fmt);
		if (fmt == AFMT_S16_LE)
			dsp->format.wBitsPerSample = 16;
		else if (fmt == AFMT_U8)
			dsp->format.wBitsPerSample = 8;
		else
		{
			log_warning("Invalid argument (can only be AFMT_S16_LE or AFMT_U8).\n");
			return -EINVAL;
		}
		break;
	}
	}
	return 0;
}

static const struct file_ops dsp_ops = {
	.close = dsp_close,
	.read = dsp_read,
	.write = dsp_write,
	.stat = virtualfs_custom_stat,
	.ioctl = dsp_ioctl,
};

static struct file *dsp_alloc();

struct virtualfs_custom_desc dsp_desc = VIRTUALFS_CUSTOM(mkdev(14, 3), dsp_alloc);

static struct file *dsp_alloc()
{
	struct dsp_file *f = (struct dsp_file *)kmalloc(sizeof(struct dsp_file));
	f->custom_file.base_file.op_vtable = &dsp_ops;
	f->custom_file.base_file.ref = 1;
	f->custom_file.base_file.flags = O_LARGEFILE | O_RDWR;
	virtualfs_init_custom(f, &dsp_desc);
	f->waveout = NULL;
	f->buffer = VirtualAlloc(NULL, DSP_BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.bInheritHandle = FALSE;
	attr.lpSecurityDescriptor = NULL;
	f->event = CreateEventW(&attr, FALSE, FALSE, NULL);
	dsp_reset(f);
	return (struct file *)f;
}
