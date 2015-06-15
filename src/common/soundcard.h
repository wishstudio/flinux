#pragma once

#define _SIOC_NONE		0U
#define _SIOC_WRITE		1U
#define _SIOC_READ		2U

#define _SIOC(dir,type,nr,size) \
	(((dir) << 30) | \
	 ((type) << 8) | \
	 ((nr) << 0) | \
	 ((size) << 16))

#define _SIO(type,nr)					_SIOC(_SIOC_NONE,(type),(nr),0)
#define _SIOR(type,nr,size)				_SIOC(_SIOC_READ,(type),(nr),sizeof(size))
#define _SIOW(type,nr,size)				_STOC(_STOC_WRITE,(type),(nr),sizeof(size))
#define _SIOWR(type, nr, size)			_SIOC(_SIOC_READ|_SIOC_WRITE,(type),(nr),sizeof(size))

/********************************************
 * IOCTL commands for /dev/dsp and /dev/audio
 */

#define SNDCTL_DSP_RESET				_SIO('P', 0)
#define SNDCTL_DSP_SYNC					_SIO('P', 1)
#define SNDCTL_DSP_SPEED				_SIOWR('P', 2, int)
#define SNDCTL_DSP_STEREO				_SIOWR('P', 3, int)
#define SNDCTL_DSP_GETBLKSIZE			_SIOWR('P', 4, int)
#define SNDCTL_DSP_SAMPLESIZE			SNDCTL_DSP_SETFMT
#define SNDCTL_DSP_CHANNELS				_SIOWR('P', 6, int)
#define SOUND_PCM_WRITE_CHANNELS		SNDCTL_DSP_CHANNELS
#define SOUND_PCM_WRITE_FILTER			_SIOWR('P', 7, int)
#define SNDCTL_DSP_POST					_SIO('P', 8)
#define SNDCTL_DSP_SUBDIVIDE			_SIOWR('P', 9, int)
#define SNDCTL_DSP_SETFRAGMENT			_SIOWR('P', 10, int)

/*      Audio data formats (Note! U8=8 and S16_LE=16 for compatibility) */
#define SNDCTL_DSP_GETFMTS				_SIOR('P', 11, int) /* Returns a mask */
#define SNDCTL_DSP_SETFMT				_SIOWR('P', 5, int) /* Selects ONE fmt*/
#		define AFMT_QUERY				0x00000000		/* Return current fmt */
#		define AFMT_MU_LAW				0x00000001
#		define AFMT_A_LAW				0x00000002
#		define AFMT_IMA_ADPCM			0x00000004
#		define AFMT_U8					0x00000008
#		define AFMT_S16_LE				0x00000010		/* Little endian signed 16*/
#		define AFMT_S16_BE				0x00000020		/* Big endian signed 16 */
#		define AFMT_S8					0x00000040
#		define AFMT_U16_LE				0x00000080		/* Little endian U16 */
#		define AFMT_U16_BE				0x00000100		/* Big endian U16 */
#		define AFMT_MPEG				0x00000200		/* MPEG (2) audio */
#		define AFMT_AC3					0x00000400		/* Dolby Digital AC3 */
