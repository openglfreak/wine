/*
 * Sample AUXILARY Wine Driver for Linux
 *
 * Copyright 1994 Martin Ayotte
 */

#define EMULATE_SB16

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "windows.h"
#include "user.h"
#include "driver.h"
#include "mmsystem.h"

#ifdef linux
#include <linux/soundcard.h>
#elif __FreeBSD__
#include <machine/soundcard.h>
#endif

#include "stddebug.h"
#include "debug.h"

#define SOUND_DEV "/dev/dsp"
#define MIXER_DEV "/dev/mixer"

#ifdef SOUND_VERSION
#define IOCTL(a,b,c)		ioctl(a,b,&c)
#else
#define IOCTL(a,b,c)		(c = ioctl(a,b,c) )
#endif


static int	NumDev = 6;

/*-----------------------------------------------------------------------*/


/**************************************************************************
 * 				AUX_GetDevCaps			[internal]
 */
static DWORD AUX_GetDevCaps(WORD wDevID, LPAUXCAPS16 lpCaps, DWORD dwSize)
{
#ifdef linux
	int 	mixer,volume;

	dprintf_mmaux(stddeb,"AUX_GetDevCaps(%04X, %p, %lu);\n", wDevID, lpCaps, dwSize);
	if (lpCaps == NULL) return MMSYSERR_NOTENABLED;
	if ((mixer = open(MIXER_DEV, O_RDWR)) < 0) {
		dprintf_mmaux(stddeb,"AUX_GetDevCaps // mixer device not available !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (ioctl(mixer, SOUND_MIXER_READ_LINE, &volume) == -1) {
		close(mixer);
		dprintf_mmaux(stddeb,"AUX_GetDevCaps // unable read mixer !\n");
		return MMSYSERR_NOTENABLED;
	}
	close(mixer);
#ifdef EMULATE_SB16
	lpCaps->wMid = 0x0002;
	lpCaps->vDriverVersion = 0x0200;
	lpCaps->dwSupport = AUXCAPS_VOLUME | AUXCAPS_LRVOLUME;
	switch (wDevID) {
		case 0:
			lpCaps->wPid = 0x0196;
			strcpy(lpCaps->szPname, "SB16 Aux: Wave");
			lpCaps->wTechnology = AUXCAPS_AUXIN;
			break;
		case 1:
			lpCaps->wPid = 0x0197;
			strcpy(lpCaps->szPname, "SB16 Aux: Midi Synth");
			lpCaps->wTechnology = AUXCAPS_AUXIN;
			break;
		case 2:
			lpCaps->wPid = 0x0191;
			strcpy(lpCaps->szPname, "SB16 Aux: CD");
			lpCaps->wTechnology = AUXCAPS_CDAUDIO;
			break;
		case 3:
			lpCaps->wPid = 0x0192;
			strcpy(lpCaps->szPname, "SB16 Aux: Line-In");
			lpCaps->wTechnology = AUXCAPS_AUXIN;
			break;
		case 4:
			lpCaps->wPid = 0x0193;
			strcpy(lpCaps->szPname, "SB16 Aux: Mic");
			lpCaps->wTechnology = AUXCAPS_AUXIN;
			break;
		case 5:
			lpCaps->wPid = 0x0194;
			strcpy(lpCaps->szPname, "SB16 Aux: Master");
			lpCaps->wTechnology = AUXCAPS_AUXIN;
			break;
		}
#else
	lpCaps->wMid = 0xAA;
	lpCaps->wPid = 0x55;
	lpCaps->vDriverVersion = 0x0100;
	strcpy(lpCaps->szPname, "Generic Linux Auxiliary Driver");
	lpCaps->wTechnology = AUXCAPS_CDAUDIO;
	lpCaps->dwSupport = AUXCAPS_VOLUME | AUXCAPS_LRVOLUME;
#endif
	return MMSYSERR_NOERROR;
#else
	return MMSYSERR_NOTENABLED;
#endif
}


/**************************************************************************
 * 				AUX_GetVolume			[internal]
 */
static DWORD AUX_GetVolume(WORD wDevID, LPDWORD lpdwVol)
{
#ifdef linux
	int 	mixer,volume,left,right,cmd;

	dprintf_mmaux(stddeb,"AUX_GetVolume(%04X, %p);\n", wDevID, lpdwVol);
	if (lpdwVol == NULL) return MMSYSERR_NOTENABLED;
	if ((mixer = open(MIXER_DEV, O_RDWR)) < 0) {
		dprintf_mmaux(stddeb,"Linux 'AUX_GetVolume' // mixer device not available !\n");
		return MMSYSERR_NOTENABLED;
	}
	switch(wDevID) {
		case 0:
			dprintf_mmaux(stddeb,"Linux 'AUX_GetVolume' // SOUND_MIXER_READ_PCM !\n");
			cmd = SOUND_MIXER_READ_PCM;
			break;
		case 1:
			dprintf_mmaux(stddeb,"Linux 'AUX_GetVolume' // SOUND_MIXER_READ_SYNTH !\n");
			cmd = SOUND_MIXER_READ_SYNTH;
			break;
		case 2:
			dprintf_mmaux(stddeb,"Linux 'AUX_GetVolume' // SOUND_MIXER_READ_CD !\n");
			cmd = SOUND_MIXER_READ_CD;
			break;
		case 3:
			dprintf_mmaux(stddeb,"Linux 'AUX_GetVolume' // SOUND_MIXER_READ_LINE !\n");
			cmd = SOUND_MIXER_READ_LINE;
			break;
		case 4:
			dprintf_mmaux(stddeb,"Linux 'AUX_GetVolume' // SOUND_MIXER_READ_MIC !\n");
			cmd = SOUND_MIXER_READ_MIC;
			break;
		case 5:
			dprintf_mmaux(stddeb,"Linux 'AUX_GetVolume' // SOUND_MIXER_READ_VOLUME !\n");
			cmd = SOUND_MIXER_READ_VOLUME;
			break;
		default:
			dprintf_mmaux(stddeb, "Linux 'AUX_GetVolume' // invalid device id=%04X !\n", wDevID);
			return MMSYSERR_NOTENABLED;
		}
	if (ioctl(mixer, cmd, &volume) == -1) {
		dprintf_mmaux(stddeb,"Linux 'AUX_GetVolume' // unable read mixer !\n");
		return MMSYSERR_NOTENABLED;
	}
	close(mixer);
	left = volume & 0x7F;
	right = (volume >> 8) & 0x7F;
	dprintf_mmaux(stddeb,"Linux 'AUX_GetVolume' // left=%d right=%d !\n", left, right);
	*lpdwVol = MAKELONG(left << 9, right << 9);
	return MMSYSERR_NOERROR;
#else
	return MMSYSERR_NOTENABLED;
#endif
}

/**************************************************************************
 * 				AUX_SetVolume			[internal]
 */
static DWORD AUX_SetVolume(WORD wDevID, DWORD dwParam)
{
#ifdef linux
	int 	mixer;
	int		volume;
	int		cmd;
	dprintf_mmaux(stddeb,"AUX_SetVolume(%04X, %08lX);\n", wDevID, dwParam);
	volume = (LOWORD(dwParam) >> 9 & 0x7F) + 
		((HIWORD(dwParam) >> 9  & 0x7F) << 8);
	if ((mixer = open(MIXER_DEV, O_RDWR)) < 0) {
		dprintf_mmaux(stddeb,"Linux 'AUX_SetVolume' // mixer device not available !\n");
		return MMSYSERR_NOTENABLED;
		}
	switch(wDevID) {
		case 0:
			dprintf_mmaux(stddeb,"Linux 'AUX_SetVolume' // SOUND_MIXER_WRITE_PCM !\n");
			cmd = SOUND_MIXER_WRITE_PCM;
			break;
		case 1:
			dprintf_mmaux(stddeb,"Linux 'AUX_SetVolume' // SOUND_MIXER_WRITE_SYNTH !\n");
			cmd = SOUND_MIXER_WRITE_SYNTH;
			break;
		case 2:
			dprintf_mmaux(stddeb,"Linux 'AUX_SetVolume' // SOUND_MIXER_WRITE_CD !\n");
			cmd = SOUND_MIXER_WRITE_CD;
			break;
		case 3:
			dprintf_mmaux(stddeb,"Linux 'AUX_SetVolume' // SOUND_MIXER_WRITE_LINE !\n");
			cmd = SOUND_MIXER_WRITE_LINE;
			break;
		case 4:
			dprintf_mmaux(stddeb,"Linux 'AUX_SetVolume' // SOUND_MIXER_WRITE_MIC !\n");
			cmd = SOUND_MIXER_WRITE_MIC;
			break;
		case 5:
			dprintf_mmaux(stddeb,"Linux 'AUX_SetVolume' // SOUND_MIXER_WRITE_VOLUME !\n");
			cmd = SOUND_MIXER_WRITE_VOLUME;
			break;
		default:
			dprintf_mmaux(stddeb, "Linux 'AUX_SetVolume' // invalid device id=%04X !\n", wDevID);
			return MMSYSERR_NOTENABLED;
		}
    if (ioctl(mixer, cmd, &volume) == -1) {
		dprintf_mmaux(stddeb,"Linux 'AUX_SetVolume' // unable set mixer !\n");
		return MMSYSERR_NOTENABLED;
		}
	close(mixer);
	return MMSYSERR_NOERROR;
#else
	return MMSYSERR_NOTENABLED;
#endif
}


/**************************************************************************
 * 				auxMessage			[sample driver]
 */
DWORD auxMessage(WORD wDevID, WORD wMsg, DWORD dwUser, 
					DWORD dwParam1, DWORD dwParam2)
{
	dprintf_mmaux(stddeb,"auxMessage(%04X, %04X, %08lX, %08lX, %08lX);\n", 
			wDevID, wMsg, dwUser, dwParam1, dwParam2);
	switch(wMsg) {
	case AUXDM_GETDEVCAPS:
		return AUX_GetDevCaps(wDevID,(LPAUXCAPS16)dwParam1,dwParam2);
	case AUXDM_GETNUMDEVS:
		dprintf_mmaux(stddeb,"AUX_GetNumDevs() return %d;\n", NumDev);
		return NumDev;
	case AUXDM_GETVOLUME:
		return AUX_GetVolume(wDevID,(LPDWORD)dwParam1);
	case AUXDM_SETVOLUME:
		return AUX_SetVolume(wDevID,dwParam1);
	default:
		dprintf_mmaux(stddeb,"auxMessage // unknown message !\n");
	}
	return MMSYSERR_NOTSUPPORTED;
}
