#pragma once

#define L_TCGETS			0x5401
#define L_TCSETS			0x5402
#define L_TCSETSW			0x5403
#define L_TCSETSF			0x5404
#define L_TCGETA			0x5405
#define L_TCSETA			0x5406
#define L_TCSETAW			0x5407
#define L_TCSETAF			0x5408
#define L_TCSBRK			0x5409
#define L_TCXONC			0x540A
#define L_TCFLSH			0x540B
#define L_TIOCEXCL			0x540C
#define L_TIOCNXCL			0x540D
#define L_TIOCSCTTY			0x540E
#define L_TIOCGPGRP			0x540F
#define L_TIOCSPGRP			0x5410
#define L_TIOCOUTQ			0x5411
#define L_TIOCSTI			0x5412
#define L_TIOCGWINSZ		0x5413
#define L_TIOCSWINSZ		0x5414
#define L_TIOCMGET			0x5415
#define L_TIOCMBIS			0x5416
#define L_TIOCMBIC			0x5417
#define L_TIOCMSET			0x5418
#define L_TIOCGSOFTCAR		0x5419
#define L_TIOCSSOFTCAR		0x541A
#define L_FIONREAD			0x541B
#define L_TIOCINQ			L_FIONREAD
#define L_TIOCLINUX			0x541C
#define L_TIOCCONS			0x541D
#define L_TIOCGSERIAL		0x541E
#define L_TIOCSSERIAL		0x541F
#define L_TIOCPKT			0x5420
#define L_FIONBIO			0x5421
#define L_TIOCNOTTY			0x5422
#define L_TIOCSETD			0x5423
#define L_TIOCGETD			0x5424
#define L_TCSBRKP			0x5425
#define L_TIOCSBRK			0x5427
#define L_TIOCCBRK			0x5428
#define L_TIOCGSID			0x5429
#define L_TCGETS2			_IOR('T', 0x2A, struct termios2)
#define L_TCSETS2			_IOW('T', 0x2B, struct termios2)
#define L_TCSETSW2			_IOW('T', 0x2C, struct termios2)
#define L_TCSETSF2			_IOW('T', 0x2D, struct termios2)
#define L_TIOCGRS485		0x542E
#define L_TIOCSRS485		0x542F
#define L_TIOCGPTN			_IOR('T', 0x30, unsigned int)
#define L_TIOCSPTLCK		_IOW('T', 0x31, int)
#define L_TIOCGDEV			_IOR('T', 0x32, unsigned int)
#define L_TCGETX			0x5432
#define L_TCSETX			0x5433
#define L_TCSETXF			0x5434
#define L_TCSETXW			0x5435
#define L_TIOCSIG			_IOW('T', 0x36, int)
#define L_TIOCVHANGUP		0x5437
#define L_TIOCGPKT			_IOR('T', 0x38, int)
#define L_TIOCGPTLCK		_IOR('T', 0x39, int)
#define L_TIOCGEXCL			_IOR('T', 0x40, int)

#define L_FIONCLEX			0x5450
#define L_FIOCLEX			0x5451
#define L_FIOASYNC			0x5452
#define L_TIOCSERCONFIG		0x5453
#define L_TIOCSERGWILD		0x5454
#define L_TIOCSERSWILD		0x5455
#define L_TIOCGLCKTRMIOS	0x5456
#define L_TIOCSLCKTRMIOS	0x5457
#define L_TIOCSERGSTRUCT	0x5458
#define L_TIOCSERGETLSR		0x5459
#define L_TIOCSERGETMULTI	0x545A
#define L_TIOCSERSETMULTI	0x545B

#define L_TIOCMIWAIT		0x545C
#define L_TIOCGICOUNT		0x545D

#define L_FIOQSIZE			0x5460

#define L_TIOCPKT_DATA			0
#define L_TIOCPKT_FLUSHREAD		1
#define L_TIOCPKT_FLUSHWRITE	2
#define L_TIOCPKT_STOP			4
#define L_TIOCPKT_START			8
#define L_TIOCPKT_NOSTOP		16
#define L_TIOCPKT_DOSTOP		32
#define L_TIOCPKT_IOCTL			64

#define L_TIOCSER_TEMT			0x01
