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

#include <stdbool.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <mmreg.h>
#include <mmsystem.h>

#pragma comment(lib, "winmm.lib")

/* Each buffer should be capable of storing about 0.125 second of samples */
#define DSP_BUFFER_COUNT	16

struct dsp_buffer
{
	WAVEHDR hdr;
	HANDLE event;
	int buffer_pos;
};

struct dsp_file
{
	struct virtualfs_custom custom_file;
	HWAVEOUT waveout;
	WAVEFORMATEX format;
	struct dsp_buffer buffer[DSP_BUFFER_COUNT];
	int buffer_size;
	int current_buffer;
};

static bool dsp_test_format(WAVEFORMATEX *format)
{
	HWAVEOUT waveout;
	return waveOutOpen(&waveout, 0, format, 0, 0, WAVE_FORMAT_QUERY | CALLBACK_NULL) == MMSYSERR_NOERROR;
}

static void CALLBACK dsp_callback(HWAVEOUT hwo, UINT uMsg, DWORD_PTR dwInstance, DWORD_PTR dwParam1, DWORD_PTR dwParam2)
{
	if (uMsg == WOM_DONE)
	{
		struct dsp_file *dsp = (struct dsp_file *)dwInstance;
		WAVEHDR *hdr = (WAVEHDR *)dwParam1;
		for (int i = 0; i < DSP_BUFFER_COUNT; i++)
			if (&dsp->buffer[i].hdr == hdr)
			{
				SetEvent(dsp->buffer[i].event);
				break;
			}
	}
}

static bool dsp_send_buffer(HWAVEOUT waveout, struct dsp_buffer *buffer)
{
	int r = waveOutWrite(waveout, &buffer->hdr, sizeof(WAVEHDR));
	if (r != MMSYSERR_NOERROR)
	{
		log_error("waveOutWrite() failed, error code: %d\n", r);
		return false;
	}
	else
		return true;
}

static void dsp_reset(struct dsp_file *dsp)
{
	if (dsp->waveout)
	{
		for (int i = 0; i < DSP_BUFFER_COUNT; i++)
		{
			waveOutUnprepareHeader(dsp->waveout, &dsp->buffer[i].hdr, sizeof(WAVEHDR));
			VirtualFree(dsp->buffer[i].hdr.lpData, 0, MEM_RELEASE);
			SetEvent(dsp->buffer[i].event);
		}
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
	/* Send remaining buffer */
	if (dsp->buffer[dsp->current_buffer].buffer_pos < dsp->buffer_size)
	{
		dsp->buffer[dsp->current_buffer].hdr.dwBufferLength = dsp->buffer[dsp->current_buffer].buffer_pos;
		dsp_send_buffer(dsp->waveout, &dsp->buffer[dsp->current_buffer]);
		/* Wait for playback */
		WaitForSingleObject(dsp->buffer[dsp->current_buffer].event, INFINITE);
	}
	dsp_reset(dsp);
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
		int r = waveOutOpen(&dsp->waveout, 0, &dsp->format, (DWORD_PTR)dsp_callback, (DWORD_PTR)dsp, CALLBACK_FUNCTION);
		if (r != MMSYSERR_NOERROR)
		{
			dsp->waveout = NULL;
			log_error("waveOutOpen() failed, error code: %d\n", r);
			return 0;
		}
		/* Buffer should be capable of storing 0.125 seconds of sample */
		dsp->buffer_size = dsp->format.nAvgBytesPerSec / 8;

		log_info("DSP buffer size: %d\n", dsp->buffer_size);
		dsp->current_buffer = 0;
		for (int i = 0; i < DSP_BUFFER_COUNT; i++)
		{
			dsp->buffer[i].hdr.lpData = VirtualAlloc(NULL, dsp->buffer_size, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
			dsp->buffer[i].hdr.dwBufferLength = dsp->buffer_size;
			dsp->buffer[i].hdr.dwBytesRecorded = 0;
			dsp->buffer[i].hdr.dwUser = 0;
			dsp->buffer[i].hdr.dwFlags = 0;
			dsp->buffer[i].hdr.dwLoops = 0;
			dsp->buffer[i].hdr.lpNext = NULL;
			dsp->buffer[i].hdr.reserved = 0;
			dsp->buffer[i].buffer_pos = dsp->buffer_size;
			int r = waveOutPrepareHeader(dsp->waveout, &dsp->buffer[i].hdr, sizeof(WAVEHDR));
			if (r != MMSYSERR_NOERROR)
			{
				for (int j = 0; j < i; j++)
					waveOutUnprepareHeader(dsp->waveout, &dsp->buffer[j].hdr, sizeof(WAVEHDR));
				waveOutClose(dsp->waveout);
				dsp->waveout = NULL;
				log_error("waveOutPrepareHeader() failed, error code: %d\n", r);
				return 0;
			}
		}
	}
	size_t written = 0;
	while (count > 0)
	{
		if (dsp->buffer[dsp->current_buffer].buffer_pos == dsp->buffer_size)
		{
			WaitForSingleObject(dsp->buffer[dsp->current_buffer].event, INFINITE);
			dsp->buffer[dsp->current_buffer].buffer_pos = 0;
		}
		size_t current = min(count, (size_t)(dsp->buffer_size - dsp->buffer[dsp->current_buffer].buffer_pos));

		memcpy(dsp->buffer[dsp->current_buffer].hdr.lpData + dsp->buffer[dsp->current_buffer].buffer_pos,
			(char *)buf + written, current);
		dsp->buffer[dsp->current_buffer].buffer_pos += current;
		if (dsp->buffer[dsp->current_buffer].buffer_pos == dsp->buffer_size)
		{
			bool ok = dsp_send_buffer(dsp->waveout, &dsp->buffer[dsp->current_buffer]);
			dsp->current_buffer = (dsp->current_buffer + 1) % DSP_BUFFER_COUNT;
			if (!ok)
				return written;
		}
		written += current;
		count -= current;
	}
	return written;
}

static int dsp_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
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
		DWORD old_speed = dsp->format.nSamplesPerSec;
		dsp->format.nSamplesPerSec = speed;
		if (!dsp_test_format(&dsp->format))
		{
			log_warning("Speed not supported.\n");
			dsp->format.nSamplesPerSec = old_speed;
			return -EINVAL;
		}
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
	case SNDCTL_DSP_GETFMTS:
	{
		if (!mm_check_write((int *)arg, sizeof(int)))
			return -EFAULT;
		log_info("SNDCTL_DSP_GETFMTS\n");
		*(int *)arg = AFMT_U8 | AFMT_S16_LE;
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
	file_init(&f->custom_file.base_file, &dsp_ops, O_LARGEFILE | O_RDWR);
	virtualfs_init_custom(f, &dsp_desc);
	f->waveout = NULL;
	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.bInheritHandle = FALSE;
	attr.lpSecurityDescriptor = NULL;
	for (int i = 0; i < DSP_BUFFER_COUNT; i++)
		f->buffer[i].event = CreateEventW(&attr, FALSE, TRUE, NULL);
	dsp_reset(f);
	return (struct file *)f;
}
