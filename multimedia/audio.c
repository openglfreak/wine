/*				   
 * Sample Wine Driver for Linux
 *
 * Copyright 1994 Martin Ayotte
 */
/*
 * FIXME:
 *	- record/play should and must be done asynchronous
 *	- segmented/linear pointer problems (lpData in waveheaders,W*_DONE cbs)
 */

#define EMULATE_SB16

#define DEBUG_MCIWAVE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "windows.h"
#include "user.h"
#include "driver.h"
#include "mmsystem.h"
#include "heap.h"
#include "ldt.h"

#ifdef linux
#include <linux/soundcard.h>
#elif __FreeBSD__
#include <machine/soundcard.h>
#endif

#include "stddebug.h"
#include "debug.h"

#if defined(linux) || defined(__FreeBSD__)
#define SOUND_DEV "/dev/dsp"
#define MIXER_DEV "/dev/mixer"

#ifdef SOUND_VERSION
#define IOCTL(a,b,c)		((-1==ioctl(a,b,&c))&&(perror("ioctl:"#b":"#c),0))
#else
#define IOCTL(a,b,c)		(c = ioctl(a,b,c) )
#endif

#define MAX_WAVOUTDRV 	(1)
#define MAX_WAVINDRV 	(1)
#define MAX_MCIWAVDRV 	(1)

typedef struct {
	int		unixdev;
	int		state;
	DWORD		bufsize;
	WAVEOPENDESC	waveDesc;
	WORD		wFlags;
	PCMWAVEFORMAT	Format;
	LPWAVEHDR	lpQueueHdr;
	DWORD		dwTotalPlayed;
} LINUX_WAVEOUT;

typedef struct {
	int		unixdev;
	int		state;
	DWORD		bufsize;	/* Linux '/dev/dsp' give us that size */
	WAVEOPENDESC	waveDesc;
	WORD		wFlags;
	PCMWAVEFORMAT	Format;
	LPWAVEHDR	lpQueueHdr;
	DWORD		dwTotalRecorded;
} LINUX_WAVEIN;

typedef struct {
        int		nUseCount;	/* Incremented for each shared open */
	BOOL16		fShareable;	/* TRUE if first open was shareable */
	WORD		wNotifyDeviceID;/* MCI device ID with a pending notification */
	HANDLE16	hCallback;	/* Callback handle for pending notification */
	HMMIO16		hFile;		/* mmio file handle open as Element */
	MCI_WAVE_OPEN_PARMS16 openParms;
	PCMWAVEFORMAT	WaveFormat;
	WAVEHDR		WaveHdr;
	BOOL16		fInput;		/* FALSE = Output, TRUE = Input */
} LINUX_MCIWAVE;

static LINUX_WAVEOUT	WOutDev[MAX_WAVOUTDRV];
static LINUX_WAVEIN	WInDev[MAX_WAVOUTDRV];
static LINUX_MCIWAVE	MCIWavDev[MAX_MCIWAVDRV];


/**************************************************************************
 * 			WAVE_NotifyClient			[internal]
 */
static DWORD WAVE_NotifyClient(UINT16 wDevID, WORD wMsg, 
				DWORD dwParam1, DWORD dwParam2)
{
	dprintf_mciwave(stddeb,"WAVE_NotifyClient // wDevID = %04X wMsg = %d dwParm1 = %04lX dwParam2 = %04lX\n",wDevID, wMsg, dwParam1, dwParam2);

	switch (wMsg) {
	case WOM_OPEN:
	case WOM_CLOSE:
	case WOM_DONE:
	  if (wDevID > MAX_WAVOUTDRV) return MCIERR_INTERNAL;
	  
	  if (WOutDev[wDevID].wFlags != DCB_NULL && !DriverCallback(
		WOutDev[wDevID].waveDesc.dwCallBack, 
		WOutDev[wDevID].wFlags, 
		WOutDev[wDevID].waveDesc.hWave, 
                wMsg, 
		WOutDev[wDevID].waveDesc.dwInstance, 
                dwParam1, 
                dwParam2)) {
	    dprintf_mciwave(stddeb,"WAVE_NotifyClient // can't notify client !\n");
	    return MMSYSERR_NOERROR;
	  }
	  break;

	case WIM_OPEN:
	case WIM_CLOSE:
	case WIM_DATA:
	  if (wDevID > MAX_WAVINDRV) return MCIERR_INTERNAL;
	  
	  if (WInDev[wDevID].wFlags != DCB_NULL && !DriverCallback(
		WInDev[wDevID].waveDesc.dwCallBack, WInDev[wDevID].wFlags, 
		WInDev[wDevID].waveDesc.hWave, wMsg, 
		WInDev[wDevID].waveDesc.dwInstance, dwParam1, dwParam2)) {
	    dprintf_mciwave(stddeb,"WAVE_NotifyClient // can't notify client !\n");
	    return MMSYSERR_NOERROR;
	  }
	  break;
	}
        return 0;
}


/**************************************************************************
 * 			WAVE_mciOpen	                        [internal]
 */
static DWORD WAVE_mciOpen(UINT16 wDevID, DWORD dwFlags, LPMCI_WAVE_OPEN_PARMS16 lpParms)
{
	LPPCMWAVEFORMAT	lpWaveFormat;
	WAVEOPENDESC 	waveDesc;
	LPSTR		lpstrElementName;
	DWORD		dwRet;
	char		str[128];

	dprintf_mciwave(stddeb,"WAVE_mciOpen(%04X, %08lX, %p)\n", 
				wDevID, dwFlags, lpParms);
	if (lpParms == NULL) return MCIERR_INTERNAL;

	if (MCIWavDev[wDevID].nUseCount > 0) {
		/* The driver already open on this channel */
		/* If the driver was opened shareable before and this open specifies */
		/* shareable then increment the use count */
		if (MCIWavDev[wDevID].fShareable && (dwFlags & MCI_OPEN_SHAREABLE))
			++MCIWavDev[wDevID].nUseCount;
		else
			return MCIERR_MUST_USE_SHAREABLE;
	} else {
		MCIWavDev[wDevID].nUseCount = 1;
		MCIWavDev[wDevID].fShareable = dwFlags & MCI_OPEN_SHAREABLE;
	}

	MCIWavDev[wDevID].fInput = FALSE;

	dprintf_mciwave(stddeb,"WAVE_mciOpen // wDevID=%04X\n", wDevID);
	dprintf_mciwave(stddeb,"WAVE_mciOpen // before OPEN_ELEMENT\n");
	if (dwFlags & MCI_OPEN_ELEMENT) {
		lpstrElementName = (LPSTR)PTR_SEG_TO_LIN(lpParms->lpstrElementName);
		dprintf_mciwave(stddeb,"WAVE_mciOpen // MCI_OPEN_ELEMENT '%s' !\n",
						lpstrElementName);
		if ( lpstrElementName && (strlen(lpstrElementName) > 0)) {
			strcpy(str, lpstrElementName);
			CharUpper32A(str);
			MCIWavDev[wDevID].hFile = mmioOpen16(str, NULL, 
				MMIO_ALLOCBUF | MMIO_READWRITE | MMIO_EXCLUSIVE);
			if (MCIWavDev[wDevID].hFile == 0) {
				dprintf_mciwave(stddeb,"WAVE_mciOpen // can't find file='%s' !\n", str);
				return MCIERR_FILE_NOT_FOUND;
			}
		}
		else 
			MCIWavDev[wDevID].hFile = 0;
	}
	dprintf_mciwave(stddeb,"WAVE_mciOpen // hFile=%u\n", MCIWavDev[wDevID].hFile);
	memcpy(&MCIWavDev[wDevID].openParms, lpParms, sizeof(MCI_WAVE_OPEN_PARMS16));
	MCIWavDev[wDevID].wNotifyDeviceID = lpParms->wDeviceID;
	lpWaveFormat = &MCIWavDev[wDevID].WaveFormat;

	waveDesc.hWave = 0;
/*
	lpWaveFormat->wf.wFormatTag = WAVE_FORMAT_PCM;
	lpWaveFormat->wBitsPerSample = 8;
	lpWaveFormat->wf.nChannels = 1;
	lpWaveFormat->wf.nSamplesPerSec = 11025;
	lpWaveFormat->wf.nAvgBytesPerSec = 11025;
	lpWaveFormat->wf.nBlockAlign = 1;
*/
	if (MCIWavDev[wDevID].hFile != 0) {
		MMCKINFO	mmckInfo;
		MMCKINFO	ckMainRIFF;
		if (mmioDescend(MCIWavDev[wDevID].hFile, &ckMainRIFF, NULL, 0) != 0)
			return MCIERR_INTERNAL;
		dprintf_mciwave(stddeb,
				"WAVE_mciOpen // ParentChunk ckid=%.4s fccType=%.4s cksize=%08lX \n",
				(LPSTR)&ckMainRIFF.ckid, (LPSTR)&ckMainRIFF.fccType,
				ckMainRIFF.cksize);
		if ((ckMainRIFF.ckid != FOURCC_RIFF) ||
		    (ckMainRIFF.fccType != mmioFOURCC('W', 'A', 'V', 'E')))
			return MCIERR_INTERNAL;
		mmckInfo.ckid = mmioFOURCC('f', 'm', 't', ' ');
		if (mmioDescend(MCIWavDev[wDevID].hFile, &mmckInfo, &ckMainRIFF, MMIO_FINDCHUNK) != 0)
			return MCIERR_INTERNAL;
		dprintf_mciwave(stddeb,
				"WAVE_mciOpen // Chunk Found ckid=%.4s fccType=%.4s cksize=%08lX \n",
				(LPSTR)&mmckInfo.ckid, (LPSTR)&mmckInfo.fccType,
				mmckInfo.cksize);
		if (mmioRead(MCIWavDev[wDevID].hFile, (HPSTR) lpWaveFormat,
		    (long) sizeof(PCMWAVEFORMAT)) != (long) sizeof(PCMWAVEFORMAT))
			return MCIERR_INTERNAL;
		mmckInfo.ckid = mmioFOURCC('d', 'a', 't', 'a');
		if (mmioDescend(MCIWavDev[wDevID].hFile, &mmckInfo, &ckMainRIFF, MMIO_FINDCHUNK) != 0)
			return MCIERR_INTERNAL;
		dprintf_mciwave(stddeb,
				"WAVE_mciOpen // Chunk Found ckid=%.4s fccType=%.4s cksize=%08lX \n",
				(LPSTR)&mmckInfo.ckid, (LPSTR)&mmckInfo.fccType,
				mmckInfo.cksize);
		dprintf_mciwave(stddeb,
			"WAVE_mciOpen // nChannels=%d nSamplesPerSec=%ld\n",
			lpWaveFormat->wf.nChannels, lpWaveFormat->wf.nSamplesPerSec);
		lpWaveFormat->wBitsPerSample = 0;
	}
	lpWaveFormat->wf.nAvgBytesPerSec = 
		lpWaveFormat->wf.nSamplesPerSec * lpWaveFormat->wf.nBlockAlign;
	waveDesc.lpFormat = (LPWAVEFORMAT)lpWaveFormat;

/*
   By default the device will be opened for output, the MCI_CUE function is there to
   change from output to input and back
*/

	dwRet=wodMessage(wDevID,WODM_OPEN,0,(DWORD)&waveDesc,CALLBACK_NULL);
	return 0;
}

/**************************************************************************
 *                               WAVE_mciCue             [internal]
 */

static DWORD WAVE_mciCue(UINT16 wDevID, DWORD dwParam, LPMCI_GENERIC_PARMS lpParms)
{
/*
   FIXME

   This routine is far from complete. At the moment only a check is done on the
   MCI_WAVE_INPUT flag. No explicit check on MCI_WAVE_OUTPUT is done since that
   is the default.

   The flags MCI_NOTIFY (and the callback parameter in lpParms) and MCI_WAIT
   are ignored
*/

        DWORD		dwRet;
        WAVEOPENDESC	waveDesc;

	dprintf_mciwave(stddeb,"WAVE_mciCue(%u, %08lX, %p);\n", wDevID, dwParam, lpParms);

/* always close elements ? */

	if (MCIWavDev[wDevID].hFile != 0) {
	  mmioClose(MCIWavDev[wDevID].hFile, 0);
	  MCIWavDev[wDevID].hFile = 0;
	}

	dwRet = MMSYSERR_NOERROR;  /* assume success */
	if ((dwParam & MCI_WAVE_INPUT) && !MCIWavDev[wDevID].fInput) {
/* FIXME this is just a hack WOutDev should be hidden here */
	        memcpy(&waveDesc,&WOutDev[wDevID].waveDesc,sizeof(WAVEOPENDESC));

	        dwRet = wodMessage(wDevID, WODM_CLOSE, 0, 0L, 0L);
	        if (dwRet != MMSYSERR_NOERROR) return MCIERR_INTERNAL;
	        dwRet = widMessage(wDevID, WIDM_OPEN, 0, (DWORD)&waveDesc, CALLBACK_NULL);
		MCIWavDev[wDevID].fInput = TRUE;
	}
	else if (MCIWavDev[wDevID].fInput) {
/* FIXME this is just a hack WInDev should be hidden here */
	        memcpy(&waveDesc,&WInDev[wDevID].waveDesc,sizeof(WAVEOPENDESC));

	        dwRet = widMessage(wDevID, WIDM_CLOSE, 0, 0L, 0L);
	        if (dwRet != MMSYSERR_NOERROR) return MCIERR_INTERNAL;
	        dwRet = wodMessage(wDevID, WODM_OPEN, 0, (DWORD)&waveDesc, CALLBACK_NULL);
		MCIWavDev[wDevID].fInput = FALSE;
	}
        return dwRet;
}

/**************************************************************************
 *				WAVE_mciClose		[internal]
 */
static DWORD WAVE_mciClose(UINT16 wDevID, DWORD dwParam, LPMCI_GENERIC_PARMS lpParms)
{
	DWORD		dwRet;

	dprintf_mciwave(stddeb,
			"WAVE_mciClose(%u, %08lX, %p);\n", wDevID, dwParam, lpParms);
	MCIWavDev[wDevID].nUseCount--;
	if (MCIWavDev[wDevID].nUseCount == 0) {
	        if (MCIWavDev[wDevID].hFile != 0) {
		        mmioClose(MCIWavDev[wDevID].hFile, 0);
			MCIWavDev[wDevID].hFile = 0;
		}
		if (MCIWavDev[wDevID].fInput)
		        dwRet = widMessage(wDevID, WIDM_CLOSE, 0, 0L, 0L);
		else
		        dwRet = wodMessage(wDevID, WODM_CLOSE, 0, 0L, 0L);
	  
		if (dwRet != MMSYSERR_NOERROR) return MCIERR_INTERNAL;
	}
	return 0;
}


/**************************************************************************
 * 				WAVE_mciPlay		[internal]
 */
static DWORD WAVE_mciPlay(UINT16 wDevID, DWORD dwFlags, LPMCI_PLAY_PARMS lpParms)
{
	int		start, end;
	LONG		bufsize, count;
	HGLOBAL16	hData;
	LPWAVEHDR	lpWaveHdr;
	DWORD		dwRet;

	dprintf_mciwave(stddeb,
		 "WAVE_mciPlay(%u, %08lX, %p);\n", wDevID, dwFlags, lpParms);

	if (MCIWavDev[wDevID].fInput) {
	        dprintf_mciwave(stddeb,"WAVE_mciPlay // cannot play on input device\n");
		return MCIERR_NONAPPLICABLE_FUNCTION;
	}

	if (MCIWavDev[wDevID].hFile == 0) {
                dprintf_mciwave(stddeb,"WAVE_mciPlay // can't find file='%08lx' !\n",
                        MCIWavDev[wDevID].openParms.lpstrElementName);
		return MCIERR_FILE_NOT_FOUND;
	}
	start = 1; 		end = 99999;
	if (dwFlags & MCI_FROM) {
		start = lpParms->dwFrom; 
		dprintf_mciwave(stddeb,
				"WAVE_mciPlay // MCI_FROM=%d \n", start);
	}
	if (dwFlags & MCI_TO) {
		end = lpParms->dwTo;
		dprintf_mciwave(stddeb,"WAVE_mciPlay // MCI_TO=%d \n", end);
	}
#if 0
	if (dwFlags & MCI_NOTIFY) {
        dprintf_mciwave(stddeb,
	        "WAVE_mciPlay // MCI_NOTIFY %08lX !\n", lpParms->dwCallback);
		switch(fork()) {
			case -1:
				dprintf_mciwave(stddeb,
				  "WAVE_mciPlay // Can't 'fork' process !\n");
				break;
			case 0:
				break;         
			default:
				dprintf_mciwave(stddeb,"WAVE_mciPlay // process started ! return to caller...\n");
				return 0;
			}
		}
#endif
	bufsize = 64000;
	lpWaveHdr = &MCIWavDev[wDevID].WaveHdr;
	hData = GlobalAlloc16(GMEM_MOVEABLE, bufsize);
	lpWaveHdr->lpData = (LPSTR) GlobalLock16(hData);
	lpWaveHdr->dwUser = 0L;
	lpWaveHdr->dwFlags = 0L;
	lpWaveHdr->dwLoops = 0L;
	dwRet=wodMessage(wDevID,WODM_PREPARE,0,(DWORD)lpWaveHdr,sizeof(WAVEHDR));
	while(TRUE) {
		count = mmioRead(MCIWavDev[wDevID].hFile, lpWaveHdr->lpData, bufsize);
		dprintf_mciwave(stddeb,"WAVE_mciPlay // mmioRead bufsize=%ld count=%ld\n", bufsize, count);
		if (count < 1) break;
		lpWaveHdr->dwBufferLength = count;
/*		lpWaveHdr->dwBytesRecorded = count; */
		dprintf_mciwave(stddeb,"WAVE_mciPlay // before WODM_WRITE lpWaveHdr=%p dwBufferLength=%lu dwBytesRecorded=%lu\n",
				lpWaveHdr, lpWaveHdr->dwBufferLength, lpWaveHdr->dwBytesRecorded);
		dwRet=wodMessage(wDevID,WODM_WRITE,0,(DWORD)lpWaveHdr,sizeof(WAVEHDR));
	}
	dwRet = wodMessage(wDevID,WODM_UNPREPARE,0,(DWORD)lpWaveHdr,sizeof(WAVEHDR));
	if (lpWaveHdr->lpData != NULL) {
		GlobalUnlock16(hData);
		GlobalFree16(hData);
		lpWaveHdr->lpData = NULL;
	}
	if (dwFlags & MCI_NOTIFY) {
		dprintf_mciwave(stddeb,"WAVE_mciPlay // MCI_NOTIFY_SUCCESSFUL %08lX !\n", lpParms->dwCallback);
		mciDriverNotify((HWND16)LOWORD(lpParms->dwCallback), 
			MCIWavDev[wDevID].wNotifyDeviceID, MCI_NOTIFY_SUCCESSFUL);
	}
	return 0;
}


/**************************************************************************
 * 				WAVE_mciRecord			[internal]
 */
static DWORD WAVE_mciRecord(UINT16 wDevID, DWORD dwFlags, LPMCI_RECORD_PARMS lpParms)
{
	int		       	start, end;
	LONG			bufsize;
	HGLOBAL16		hData;
	LPWAVEHDR		lpWaveHdr;
	DWORD			dwRet;

	dprintf_mciwave(stddeb,
		"WAVE_mciRecord(%u, %08lX, %p);\n", wDevID, dwFlags, lpParms);

	if (!MCIWavDev[wDevID].fInput) {
	        dprintf_mciwave(stddeb,"WAVE_mciPlay // cannot record on output device\n");
		return MCIERR_NONAPPLICABLE_FUNCTION;
	}

	if (MCIWavDev[wDevID].hFile == 0) {
		dprintf_mciwave(stddeb,"WAVE_mciRecord // can't find file='%08lx' !\n", 
				MCIWavDev[wDevID].openParms.lpstrElementName);
		return MCIERR_FILE_NOT_FOUND;
	}
	start = 1; 	end = 99999;
	if (dwFlags & MCI_FROM) {
		start = lpParms->dwFrom; 
		dprintf_mciwave(stddeb,
				"WAVE_mciRecord // MCI_FROM=%d \n", start);
	}
	if (dwFlags & MCI_TO) {
		end = lpParms->dwTo;
		dprintf_mciwave(stddeb,"WAVE_mciRecord // MCI_TO=%d \n", end);
	}
	bufsize = 64000;
	lpWaveHdr = &MCIWavDev[wDevID].WaveHdr;
	hData = GlobalAlloc16(GMEM_MOVEABLE, bufsize);
	lpWaveHdr->lpData = (LPSTR)GlobalLock16(hData);
	lpWaveHdr->dwBufferLength = bufsize;
	lpWaveHdr->dwUser = 0L;
	lpWaveHdr->dwFlags = 0L;
	lpWaveHdr->dwLoops = 0L;
	dwRet=widMessage(wDevID,WIDM_PREPARE,0,(DWORD)lpWaveHdr,sizeof(WAVEHDR));
	dprintf_mciwave(stddeb,"WAVE_mciRecord // after WIDM_PREPARE \n");
	while(TRUE) {
		lpWaveHdr->dwBytesRecorded = 0;
		dwRet = widMessage(wDevID, WIDM_START, 0, 0L, 0L);
		dprintf_mciwave(stddeb,
                    "WAVE_mciRecord // after WIDM_START lpWaveHdr=%p dwBytesRecorded=%lu\n",
					lpWaveHdr, lpWaveHdr->dwBytesRecorded);
		if (lpWaveHdr->dwBytesRecorded == 0) break;
	}
	dprintf_mciwave(stddeb,"WAVE_mciRecord // before WIDM_UNPREPARE \n");
	dwRet = widMessage(wDevID,WIDM_UNPREPARE,0,(DWORD)lpWaveHdr,sizeof(WAVEHDR));
	dprintf_mciwave(stddeb,"WAVE_mciRecord // after WIDM_UNPREPARE \n");
	if (lpWaveHdr->lpData != NULL) {
		GlobalUnlock16(hData);
		GlobalFree16(hData);
		lpWaveHdr->lpData = NULL;
	}
	if (dwFlags & MCI_NOTIFY) {
	  dprintf_mciwave(stddeb,"WAVE_mciRecord // MCI_NOTIFY_SUCCESSFUL %08lX !\n", lpParms->dwCallback);
		mciDriverNotify((HWND16)LOWORD(lpParms->dwCallback), 
			MCIWavDev[wDevID].wNotifyDeviceID, MCI_NOTIFY_SUCCESSFUL);
	}
	return 0;
}


/**************************************************************************
 * 				WAVE_mciStop			[internal]
 */
static DWORD WAVE_mciStop(UINT16 wDevID, DWORD dwFlags, LPMCI_GENERIC_PARMS lpParms)
{
        DWORD dwRet;

	dprintf_mciwave(stddeb,
		"WAVE_mciStop(%u, %08lX, %p);\n", wDevID, dwFlags, lpParms);
	if (lpParms == NULL) return MCIERR_INTERNAL;
	if (MCIWavDev[wDevID].fInput)
	  dwRet = widMessage(wDevID, WIDM_STOP, 0, dwFlags, (DWORD)lpParms);
	else
	  dwRet = wodMessage(wDevID, WODM_STOP, 0, dwFlags, (DWORD)lpParms);
	  
	return dwRet;
}


/**************************************************************************
 * 				WAVE_mciPause			[internal]
 */
static DWORD WAVE_mciPause(UINT16 wDevID, DWORD dwFlags, LPMCI_GENERIC_PARMS lpParms)
{
        DWORD dwRet;

	dprintf_mciwave(stddeb,
		"WAVE_mciPause(%u, %08lX, %p);\n", wDevID, dwFlags, lpParms);
	if (lpParms == NULL) return MCIERR_INTERNAL;
	if (MCIWavDev[wDevID].fInput)
	  dwRet = widMessage(wDevID, WIDM_PAUSE, 0, dwFlags, (DWORD)lpParms);
	else
	  dwRet = wodMessage(wDevID, WODM_PAUSE, 0, dwFlags, (DWORD)lpParms);

	return dwRet;
}


/**************************************************************************
 * 				WAVE_mciResume			[internal]
 */
static DWORD WAVE_mciResume(UINT16 wDevID, DWORD dwFlags, LPMCI_GENERIC_PARMS lpParms)
{
	dprintf_mciwave(stddeb,
		"WAVE_mciResume(%u, %08lX, %p);\n", wDevID, dwFlags, lpParms);
	if (lpParms == NULL) return MCIERR_INTERNAL;
	return 0;
}


/**************************************************************************
 * 				WAVE_mciSet			[internal]
 */
static DWORD WAVE_mciSet(UINT16 wDevID, DWORD dwFlags, LPMCI_SET_PARMS lpParms)
{
	dprintf_mciwave(stddeb,
		"WAVE_mciSet(%u, %08lX, %p);\n", wDevID, dwFlags, lpParms);
	if (lpParms == NULL) return MCIERR_INTERNAL;
	dprintf_mciwave(stddeb,
		 "WAVE_mciSet // dwTimeFormat=%08lX\n", lpParms->dwTimeFormat);
	dprintf_mciwave(stddeb,
		 "WAVE_mciSet // dwAudio=%08lX\n", lpParms->dwAudio);
	if (dwFlags & MCI_SET_TIME_FORMAT) {
		switch (lpParms->dwTimeFormat) {
		case MCI_FORMAT_MILLISECONDS:
			dprintf_mciwave(stddeb,	"WAVE_mciSet // MCI_FORMAT_MILLISECONDS !\n");
			break;
		case MCI_FORMAT_BYTES:
			dprintf_mciwave(stddeb, "WAVE_mciSet // MCI_FORMAT_BYTES !\n");
			break;
		case MCI_FORMAT_SAMPLES:
			dprintf_mciwave(stddeb,	"WAVE_mciSet // MCI_FORMAT_SAMPLES !\n");
			break;
		default:
			dprintf_mciwave(stddeb,	"WAVE_mciSet // bad time format !\n");
			return MCIERR_BAD_TIME_FORMAT;
		}
	}
	if (dwFlags & MCI_SET_VIDEO) return MCIERR_UNSUPPORTED_FUNCTION;
	if (dwFlags & MCI_SET_DOOR_OPEN) return MCIERR_UNSUPPORTED_FUNCTION;
	if (dwFlags & MCI_SET_DOOR_CLOSED) return MCIERR_UNSUPPORTED_FUNCTION;
	if (dwFlags & MCI_SET_AUDIO) 
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_SET_AUDIO !\n");
	if (dwFlags && MCI_SET_ON) {
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_SET_ON !\n");
	  if (dwFlags && MCI_SET_AUDIO_LEFT) 
	    dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_SET_AUDIO_LEFT !\n");
	  if (dwFlags && MCI_SET_AUDIO_RIGHT) 
	    dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_SET_AUDIO_RIGHT !\n");
	}
	if (dwFlags & MCI_SET_OFF) 
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_SET_OFF !\n");
	if (dwFlags & MCI_WAVE_INPUT) 
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_WAVE_INPUT !\n");
      	if (dwFlags & MCI_WAVE_OUTPUT) 
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_WAVE_OUTPUT !\n");
	if (dwFlags & MCI_WAVE_SET_ANYINPUT) 
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_WAVE_SET_ANYINPUT !\n");
	if (dwFlags & MCI_WAVE_SET_ANYOUTPUT) 
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_WAVE_SET_ANYOUTPUT !\n");
	if (dwFlags & MCI_WAVE_SET_AVGBYTESPERSEC) 
	  dprintf_mciwave(stddeb,
			  "WAVE_mciSet // MCI_WAVE_SET_AVGBYTESPERSEC !\n");
	if (dwFlags & MCI_WAVE_SET_BITSPERSAMPLE) 
	  dprintf_mciwave(stddeb,
			  "WAVE_mciSet // MCI_WAVE_SET_BITSPERSAMPLE !\n");
	if (dwFlags & MCI_WAVE_SET_BLOCKALIGN) 
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_WAVE_SET_BLOCKALIGN !\n");
	if (dwFlags & MCI_WAVE_SET_CHANNELS) 
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_WAVE_SET_CHANNELS !\n");
	if (dwFlags & MCI_WAVE_SET_FORMATTAG) 
	  dprintf_mciwave(stddeb,"WAVE_mciSet // MCI_WAVE_SET_FORMATTAG !\n");
	if (dwFlags & MCI_WAVE_SET_SAMPLESPERSEC) 
	  dprintf_mciwave(stddeb,
			  "WAVE_mciSet // MCI_WAVE_SET_SAMPLESPERSEC !\n");
 	return 0;
}


/**************************************************************************
 * 				WAVE_mciStatus		[internal]
 */
static DWORD WAVE_mciStatus(UINT16 wDevID, DWORD dwFlags, LPMCI_STATUS_PARMS lpParms)
{
	dprintf_mciwave(stddeb,
		"WAVE_mciStatus(%u, %08lX, %p);\n", wDevID, dwFlags, lpParms);
	if (lpParms == NULL) return MCIERR_INTERNAL;
	if (dwFlags & MCI_STATUS_ITEM) {
		switch(lpParms->dwItem) {
		case MCI_STATUS_CURRENT_TRACK:
			lpParms->dwReturn = 1;
			break;
		case MCI_STATUS_LENGTH:
			lpParms->dwReturn = 5555;
			if (dwFlags & MCI_TRACK) {
				lpParms->dwTrack = 1;
				lpParms->dwReturn = 2222;
				}
			break;
		case MCI_STATUS_MODE:
			lpParms->dwReturn = MCI_MODE_STOP;
			break;
		case MCI_STATUS_MEDIA_PRESENT:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_STATUS_MEDIA_PRESENT !\n");
			lpParms->dwReturn = TRUE;
			break;
		case MCI_STATUS_NUMBER_OF_TRACKS:
			lpParms->dwReturn = 1;
			break;
		case MCI_STATUS_POSITION:
			lpParms->dwReturn = 3333;
			if (dwFlags & MCI_STATUS_START)
				lpParms->dwItem = 1;
			if (dwFlags & MCI_TRACK) {
				lpParms->dwTrack = 1;
				lpParms->dwReturn = 777;
			}
			break;
		case MCI_STATUS_READY:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_STATUS_READY !\n");
			lpParms->dwReturn = TRUE;
			break;
		case MCI_STATUS_TIME_FORMAT:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_STATUS_TIME_FORMAT !\n");
			lpParms->dwReturn = MCI_FORMAT_MILLISECONDS;
			break;
		case MCI_WAVE_INPUT:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_WAVE_INPUT !\n");
			lpParms->dwReturn = 0;
			break;
		case MCI_WAVE_OUTPUT:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_WAVE_OUTPUT !\n");
			lpParms->dwReturn = 0;
			break;
		case MCI_WAVE_STATUS_AVGBYTESPERSEC:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_WAVE_STATUS_AVGBYTESPERSEC !\n");
			lpParms->dwReturn = 22050;
			break;
		case MCI_WAVE_STATUS_BITSPERSAMPLE:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_WAVE_STATUS_BITSPERSAMPLE !\n");
			lpParms->dwReturn = 8;
			break;
		case MCI_WAVE_STATUS_BLOCKALIGN:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_WAVE_STATUS_BLOCKALIGN !\n");
			lpParms->dwReturn = 1;
			break;
		case MCI_WAVE_STATUS_CHANNELS:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_WAVE_STATUS_CHANNELS !\n");
			lpParms->dwReturn = 1;
			break;
		case MCI_WAVE_STATUS_FORMATTAG:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_WAVE_FORMATTAG !\n");
			lpParms->dwReturn = WAVE_FORMAT_PCM;
			break;
		case MCI_WAVE_STATUS_LEVEL:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_WAVE_STATUS_LEVEL !\n");
			lpParms->dwReturn = 0xAAAA5555;
			break;
		case MCI_WAVE_STATUS_SAMPLESPERSEC:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_WAVE_STATUS_SAMPLESPERSEC !\n");
			lpParms->dwReturn = 22050;
			break;
		default:
			dprintf_mciwave(stddeb,"WAVE_mciStatus // unknown command %08lX !\n", lpParms->dwItem);
			return MCIERR_UNRECOGNIZED_COMMAND;
		}
	}
	if (dwFlags & MCI_NOTIFY) {
		dprintf_mciwave(stddeb,"WAVE_mciStatus // MCI_NOTIFY_SUCCESSFUL %08lX !\n", lpParms->dwCallback);
		mciDriverNotify((HWND16)LOWORD(lpParms->dwCallback), 
			MCIWavDev[wDevID].wNotifyDeviceID, MCI_NOTIFY_SUCCESSFUL);
	}
 	return 0;
}

/**************************************************************************
 * 				WAVE_mciGetDevCaps		[internal]
 */
static DWORD WAVE_mciGetDevCaps(UINT16 wDevID, DWORD dwFlags, 
					LPMCI_GETDEVCAPS_PARMS lpParms)
{
	dprintf_mciwave(stddeb,
		"WAVE_mciGetDevCaps(%u, %08lX, %p);\n", wDevID, dwFlags, lpParms);
	if (lpParms == NULL) return MCIERR_INTERNAL;
	if (dwFlags & MCI_GETDEVCAPS_ITEM) {
		switch(lpParms->dwItem) {
		case MCI_GETDEVCAPS_CAN_RECORD:
			lpParms->dwReturn = TRUE;
			break;
		case MCI_GETDEVCAPS_HAS_AUDIO:
			lpParms->dwReturn = TRUE;
			break;
		case MCI_GETDEVCAPS_HAS_VIDEO:
			lpParms->dwReturn = FALSE;
			break;
		case MCI_GETDEVCAPS_DEVICE_TYPE:
			lpParms->dwReturn = MCI_DEVTYPE_WAVEFORM_AUDIO;
			break;
		case MCI_GETDEVCAPS_USES_FILES:
			lpParms->dwReturn = TRUE;
			break;
		case MCI_GETDEVCAPS_COMPOUND_DEVICE:
			lpParms->dwReturn = TRUE;
			break;
		case MCI_GETDEVCAPS_CAN_EJECT:
			lpParms->dwReturn = FALSE;
			break;
		case MCI_GETDEVCAPS_CAN_PLAY:
			lpParms->dwReturn = TRUE;
			break;
		case MCI_GETDEVCAPS_CAN_SAVE:
			lpParms->dwReturn = TRUE;
			break;
		case MCI_WAVE_GETDEVCAPS_INPUTS:
			lpParms->dwReturn = 1;
			break;
		case MCI_WAVE_GETDEVCAPS_OUTPUTS:
			lpParms->dwReturn = 1;
			break;
		default:
			return MCIERR_UNRECOGNIZED_COMMAND;
		}
	}
 	return 0;
}

/**************************************************************************
 * 				WAVE_mciInfo			[internal]
 */
static DWORD WAVE_mciInfo(UINT16 wDevID, DWORD dwFlags, LPMCI_INFO_PARMS16 lpParms)
{
	dprintf_mciwave(stddeb,
		"WAVE_mciInfo(%u, %08lX, %p);\n", wDevID, dwFlags, lpParms);
	if (lpParms == NULL) return MCIERR_INTERNAL;
	lpParms->lpstrReturn = NULL;
	switch(dwFlags) {
	case MCI_INFO_PRODUCT:
		lpParms->lpstrReturn = "Linux Sound System 0.5";
		break;
	case MCI_INFO_FILE:
		lpParms->lpstrReturn = 
			(LPSTR)MCIWavDev[wDevID].openParms.lpstrElementName;
		break;
	case MCI_WAVE_INPUT:
		lpParms->lpstrReturn = "Linux Sound System 0.5";
		break;
	case MCI_WAVE_OUTPUT:
		lpParms->lpstrReturn = "Linux Sound System 0.5";
		break;
	default:
		return MCIERR_UNRECOGNIZED_COMMAND;
	}
	if (lpParms->lpstrReturn != NULL)
		lpParms->dwRetSize = strlen(lpParms->lpstrReturn);
	else
		lpParms->dwRetSize = 0;
 	return 0;
}


/*-----------------------------------------------------------------------*/


/**************************************************************************
 * 			wodGetDevCaps				[internal]
 */
static DWORD wodGetDevCaps(WORD wDevID, LPWAVEOUTCAPS16 lpCaps, DWORD dwSize)
{
	int 	audio;
	int	smplrate;
	int	samplesize = 16;
	int	dsp_stereo = 1;
	int	bytespersmpl;

	dprintf_mciwave(stddeb,
		   "wodGetDevCaps(%u, %p, %lu);\n", wDevID, lpCaps, dwSize);
	if (lpCaps == NULL) return MMSYSERR_NOTENABLED;
	if (access(SOUND_DEV,0) != 0) return MMSYSERR_NOTENABLED;
	audio = open (SOUND_DEV, O_WRONLY, 0);
	if (audio == -1) return MMSYSERR_ALLOCATED ;
#ifdef EMULATE_SB16
	lpCaps->wMid = 0x0002;
	lpCaps->wPid = 0x0104;
	strcpy(lpCaps->szPname, "SB16 Wave Out");
#else
	lpCaps->wMid = 0x00FF; 	/* Manufac ID */
	lpCaps->wPid = 0x0001; 	/* Product ID */
	strcpy(lpCaps->szPname, "Linux WAVOUT Driver");
#endif
	lpCaps->vDriverVersion = 0x0100;
	lpCaps->dwFormats = 0x00000000;
	lpCaps->dwSupport = WAVECAPS_VOLUME;
	lpCaps->wChannels = (IOCTL(audio, SNDCTL_DSP_STEREO, dsp_stereo) != 0) ? 1 : 2;
	if (lpCaps->wChannels > 1) lpCaps->dwSupport |= WAVECAPS_LRVOLUME;
	bytespersmpl = (IOCTL(audio, SNDCTL_DSP_SAMPLESIZE, samplesize) != 0) ? 1 : 2;
	smplrate = 44100;
	if (IOCTL(audio, SNDCTL_DSP_SPEED, smplrate) == 0) {
		lpCaps->dwFormats |= WAVE_FORMAT_4M08;
		if (lpCaps->wChannels > 1)
			lpCaps->dwFormats |= WAVE_FORMAT_4S08;
		if (bytespersmpl > 1) {
			lpCaps->dwFormats |= WAVE_FORMAT_4M16;
			if (lpCaps->wChannels > 1)
				lpCaps->dwFormats |= WAVE_FORMAT_4S16;
		}
	}
	smplrate = 22050;
	if (IOCTL(audio, SNDCTL_DSP_SPEED, smplrate) == 0) {
		lpCaps->dwFormats |= WAVE_FORMAT_2M08;
		if (lpCaps->wChannels > 1)
			lpCaps->dwFormats |= WAVE_FORMAT_2S08;
		if (bytespersmpl > 1) {
			lpCaps->dwFormats |= WAVE_FORMAT_2M16;
			if (lpCaps->wChannels > 1)
				lpCaps->dwFormats |= WAVE_FORMAT_2S16;
		}
	}
	smplrate = 11025;
	if (IOCTL(audio, SNDCTL_DSP_SPEED, smplrate) == 0) {
		lpCaps->dwFormats |= WAVE_FORMAT_1M08;
		if (lpCaps->wChannels > 1)
			lpCaps->dwFormats |= WAVE_FORMAT_1S08;
		if (bytespersmpl > 1) {
			lpCaps->dwFormats |= WAVE_FORMAT_1M16;
			if (lpCaps->wChannels > 1)
				lpCaps->dwFormats |= WAVE_FORMAT_1S16;
		}
	}
	close(audio);
	dprintf_mciwave(stddeb,
		"wodGetDevCaps // dwFormats = %08lX\n", lpCaps->dwFormats);
	return MMSYSERR_NOERROR;
}


/**************************************************************************
 * 				wodOpen				[internal]
 */
static DWORD wodOpen(WORD wDevID, LPWAVEOPENDESC lpDesc, DWORD dwFlags)
{
	int 	 audio,abuf_size,smplrate,samplesize,dsp_stereo;
	LPWAVEFORMAT	lpFormat;

	dprintf_mciwave(stddeb,
		"wodOpen(%u, %p, %08lX);\n", wDevID, lpDesc, dwFlags);
	if (lpDesc == NULL) {
		dprintf_mciwave(stddeb,"Linux 'wodOpen' // Invalid Parameter !\n");
		return MMSYSERR_INVALPARAM;
	}
	if (wDevID >= MAX_WAVOUTDRV) {
		dprintf_mciwave(stddeb,"Linux 'wodOpen' // MAX_WAVOUTDRV reached !\n");
		return MMSYSERR_ALLOCATED;
	}
	WOutDev[wDevID].unixdev = 0;
	if (access(SOUND_DEV,0) != 0) return MMSYSERR_NOTENABLED;
	audio = open (SOUND_DEV, O_WRONLY, 0);
	if (audio == -1) {
		dprintf_mciwave(stddeb,"Linux 'wodOpen' // can't open !\n");
		return MMSYSERR_ALLOCATED ;
	}
	IOCTL(audio, SNDCTL_DSP_GETBLKSIZE, abuf_size);
	if (abuf_size < 1024 || abuf_size > 65536) {
		if (abuf_size == -1)
			dprintf_mciwave(stddeb,"Linux 'wodOpen' // IOCTL can't 'SNDCTL_DSP_GETBLKSIZE' !\n");
		else
			dprintf_mciwave(stddeb,"Linux 'wodOpen' // SNDCTL_DSP_GETBLKSIZE Invalid bufsize !\n");
		return MMSYSERR_NOTENABLED;
	}
	WOutDev[wDevID].wFlags = HIWORD(dwFlags & CALLBACK_TYPEMASK);
	switch(WOutDev[wDevID].wFlags) {
	case DCB_NULL:
		dprintf_mciwave(stddeb,	"Linux 'wodOpen' // CALLBACK_NULL !\n");
		break;
	case DCB_WINDOW:
		dprintf_mciwave(stddeb,	"Linux 'wodOpen' // CALLBACK_WINDOW !\n");
		break;
	case DCB_TASK:
		dprintf_mciwave(stddeb,	"Linux 'wodOpen' // CALLBACK_TASK !\n");
		break;
	case DCB_FUNCTION:
		dprintf_mciwave(stddeb,	"Linux 'wodOpen' // CALLBACK_FUNCTION !\n");
		break;
	}
	WOutDev[wDevID].lpQueueHdr = NULL;
	WOutDev[wDevID].unixdev = audio;
	WOutDev[wDevID].dwTotalPlayed = 0;
	WOutDev[wDevID].bufsize = abuf_size;
	/* FIXME: copy lpFormat too? */
	memcpy(&WOutDev[wDevID].waveDesc, lpDesc, sizeof(WAVEOPENDESC));
	dprintf_mciwave(stddeb,"Linux 'wodOpen' // lpDesc->lpFormat = %p\n",lpDesc->lpFormat);
        lpFormat = lpDesc->lpFormat; 
	dprintf_mciwave(stddeb,"Linux 'wodOpen' // lpFormat = %p\n",lpFormat);
	if (lpFormat->wFormatTag != WAVE_FORMAT_PCM) {
		dprintf_mciwave(stddeb,"Linux 'wodOpen' // Bad format %04X !\n",
				lpFormat->wFormatTag);
		dprintf_mciwave(stddeb,"Linux 'wodOpen' // Bad nChannels %d !\n",
				lpFormat->nChannels);
		dprintf_mciwave(stddeb,"Linux 'wodOpen' // Bad nSamplesPerSec %ld !\n",
				lpFormat->nSamplesPerSec);
		return WAVERR_BADFORMAT;
	}
	memcpy(&WOutDev[wDevID].Format, lpFormat, sizeof(PCMWAVEFORMAT));
	if (WOutDev[wDevID].Format.wf.nChannels == 0) return WAVERR_BADFORMAT;
	if (WOutDev[wDevID].Format.wf.nSamplesPerSec == 0) return WAVERR_BADFORMAT;
	dprintf_mciwave(stddeb,"Linux 'wodOpen' // wBitsPerSample=%u !\n",
				WOutDev[wDevID].Format.wBitsPerSample);
	if (WOutDev[wDevID].Format.wBitsPerSample == 0) {
		WOutDev[wDevID].Format.wBitsPerSample = 8 *
		(WOutDev[wDevID].Format.wf.nAvgBytesPerSec /
		WOutDev[wDevID].Format.wf.nSamplesPerSec) /
		WOutDev[wDevID].Format.wf.nChannels;
	}
	samplesize = WOutDev[wDevID].Format.wBitsPerSample;
	smplrate = WOutDev[wDevID].Format.wf.nSamplesPerSec;
	dsp_stereo = (WOutDev[wDevID].Format.wf.nChannels > 1) ? TRUE : FALSE;
	IOCTL(audio, SNDCTL_DSP_SPEED, smplrate);
	IOCTL(audio, SNDCTL_DSP_SAMPLESIZE, samplesize);
	IOCTL(audio, SNDCTL_DSP_STEREO, dsp_stereo);
	dprintf_mciwave(stddeb,"Linux 'wodOpen' // wBitsPerSample=%u !\n",
				WOutDev[wDevID].Format.wBitsPerSample);
	dprintf_mciwave(stddeb,"Linux 'wodOpen' // nAvgBytesPerSec=%lu !\n",
				WOutDev[wDevID].Format.wf.nAvgBytesPerSec);
	dprintf_mciwave(stddeb,"Linux 'wodOpen' // nSamplesPerSec=%lu !\n",
				WOutDev[wDevID].Format.wf.nSamplesPerSec);
	dprintf_mciwave(stddeb,"Linux 'wodOpen' // nChannels=%u !\n",
				WOutDev[wDevID].Format.wf.nChannels);
	if (WAVE_NotifyClient(wDevID, WOM_OPEN, 0L, 0L) != MMSYSERR_NOERROR) {
		dprintf_mciwave(stddeb,"Linux 'wodOpen' // can't notify client !\n");
		return MMSYSERR_INVALPARAM;
	}
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				wodClose			[internal]
 */
static DWORD wodClose(WORD wDevID)
{
	dprintf_mciwave(stddeb,"wodClose(%u);\n", wDevID);
	if (wDevID > MAX_WAVOUTDRV) return MMSYSERR_INVALPARAM;
	if (WOutDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'wodClose' // can't close !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (WOutDev[wDevID].lpQueueHdr != NULL) {
	        dprintf_mciwave(stddeb,"linux 'wodclose' // still buffers open !\n");
		/* Don't care. Who needs those buffers anyway */
		/*return WAVERR_STILLPLAYING; */
	}
	close(WOutDev[wDevID].unixdev);
	WOutDev[wDevID].unixdev = 0;
	WOutDev[wDevID].bufsize = 0;
	WOutDev[wDevID].lpQueueHdr = NULL;
	if (WAVE_NotifyClient(wDevID, WOM_CLOSE, 0L, 0L) != MMSYSERR_NOERROR) {
		dprintf_mciwave(stddeb,"Linux 'wodClose' // can't notify client !\n");
		return MMSYSERR_INVALPARAM;
	}
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				wodWrite			[internal]
 * FIXME: this should _APPEND_ the lpWaveHdr to the output queue of the
 * device, and initiate async playing.
 */
static DWORD wodWrite(WORD wDevID, LPWAVEHDR lpWaveHdr, DWORD dwSize)
{
	int		count;
	LPSTR	        lpData;
	LPWAVEHDR	xwavehdr;

	dprintf_mciwave(stddeb,"wodWrite(%u, %p, %08lX);\n", wDevID, lpWaveHdr, dwSize);
	if (WOutDev[wDevID].unixdev == 0) {
        dprintf_mciwave(stddeb,"Linux 'wodWrite' // can't play !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (lpWaveHdr->lpData == NULL) return WAVERR_UNPREPARED;
	if (!(lpWaveHdr->dwFlags & WHDR_PREPARED)) return WAVERR_UNPREPARED;
	if (lpWaveHdr->dwFlags & WHDR_INQUEUE) return WAVERR_STILLPLAYING;
	lpWaveHdr->dwFlags &= ~WHDR_DONE;
	lpWaveHdr->dwFlags |= WHDR_INQUEUE;
	dprintf_mciwave(stddeb,
		"wodWrite() // dwBufferLength %lu !\n", lpWaveHdr->dwBufferLength);
	dprintf_mciwave(stddeb,
		"wodWrite() // WOutDev[%u].unixdev %u !\n", wDevID, WOutDev[wDevID].unixdev);
	lpData = lpWaveHdr->lpData;
	count = write (WOutDev[wDevID].unixdev, lpData, lpWaveHdr->dwBufferLength);
	dprintf_mciwave(stddeb,"wodWrite()//write returned count %u !\n",count);
	if (count != lpWaveHdr->dwBufferLength) {
		dprintf_mciwave(stddeb,"Linux 'wodWrite' // error writting !\n");
		return MMSYSERR_NOTENABLED;
	}
	WOutDev[wDevID].dwTotalPlayed += count;
	lpWaveHdr->dwFlags &= ~WHDR_INQUEUE;
	lpWaveHdr->dwFlags |= WHDR_DONE;
	if ((DWORD)lpWaveHdr->lpData!=lpWaveHdr->reserved) {
		/* FIXME: what if it expects it's OWN lpwavehdr back? */
		xwavehdr = SEGPTR_NEW(WAVEHDR);
		memcpy(xwavehdr,lpWaveHdr,sizeof(WAVEHDR));
		xwavehdr->lpData = (LPBYTE)xwavehdr->reserved;
		if (WAVE_NotifyClient(wDevID, WOM_DONE, (DWORD)SEGPTR_GET(xwavehdr), count) != MMSYSERR_NOERROR) {
			dprintf_mciwave(stddeb,"Linux 'wodWrite' // can't notify client !\n");
			SEGPTR_FREE(xwavehdr);
			return MMSYSERR_INVALPARAM;
		}
		SEGPTR_FREE(xwavehdr);
	} else {
		if (WAVE_NotifyClient(wDevID, WOM_DONE, (DWORD)lpWaveHdr, count) != MMSYSERR_NOERROR) {
			dprintf_mciwave(stddeb,"Linux 'wodWrite' // can't notify client !\n");
			return MMSYSERR_INVALPARAM;
		}
	}
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				wodPrepare			[internal]
 */
static DWORD wodPrepare(WORD wDevID, LPWAVEHDR lpWaveHdr, DWORD dwSize)
{
	dprintf_mciwave(stddeb,
		"wodPrepare(%u, %p, %08lX);\n", wDevID, lpWaveHdr, dwSize);
	if (WOutDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'wodPrepare' // can't prepare !\n");
		return MMSYSERR_NOTENABLED;
	}
	/* don't append to queue, wodWrite does that */
	WOutDev[wDevID].dwTotalPlayed = 0;
	if (lpWaveHdr->dwFlags & WHDR_INQUEUE)
		return WAVERR_STILLPLAYING;
	lpWaveHdr->dwFlags |= WHDR_PREPARED;
	lpWaveHdr->dwFlags &= ~WHDR_DONE;
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				wodUnprepare			[internal]
 */
static DWORD wodUnprepare(WORD wDevID, LPWAVEHDR lpWaveHdr, DWORD dwSize)
{
	dprintf_mciwave(stddeb,
		"wodUnprepare(%u, %p, %08lX);\n", wDevID, lpWaveHdr, dwSize);
	if (WOutDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'wodUnprepare' // can't unprepare !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (lpWaveHdr->dwFlags & WHDR_INQUEUE)
		return WAVERR_STILLPLAYING;
	
	lpWaveHdr->dwFlags &= ~WHDR_PREPARED;
	lpWaveHdr->dwFlags |= WHDR_DONE;
	dprintf_mciwave(stddeb,
		"Linux 'wodUnprepare' // all headers unprepared !\n");
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 			wodRestart				[internal]
 */
static DWORD wodRestart(WORD wDevID)
{
	dprintf_mciwave(stddeb,"wodRestart(%u);\n", wDevID);
	if (WOutDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'wodRestart' // can't restart !\n");
		return MMSYSERR_NOTENABLED;
	}
	/* FIXME: is NotifyClient with WOM_DONE right ? (Comet Busters 1.3.3 needs this notification) */
       	if (WAVE_NotifyClient(wDevID, WOM_DONE, 0L, 0L) != MMSYSERR_NOERROR) {
               	dprintf_mciwave(stddeb,"Linux 'wodRestart' // can't notify client !\n");
               	return MMSYSERR_INVALPARAM;
        }

	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 			wodReset				[internal]
 */
static DWORD wodReset(WORD wDevID)
{
	dprintf_mciwave(stddeb,"wodReset(%u);\n", wDevID);
	if (WOutDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'wodReset' // can't reset !\n");
		return MMSYSERR_NOTENABLED;
		}
	return MMSYSERR_NOERROR;
}


/**************************************************************************
 * 				wodGetPosition			[internal]
 */
static DWORD wodGetPosition(WORD wDevID, LPMMTIME16 lpTime, DWORD uSize)
{
	int		time;
	dprintf_mciwave(stddeb,"wodGetPosition(%u, %p, %lu);\n", wDevID, lpTime, uSize);
	if (WOutDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'wodGetPosition' // can't get pos !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (lpTime == NULL)	return MMSYSERR_INVALPARAM;
	dprintf_mciwave(stddeb,"wodGetPosition // wType=%04X !\n", 
			lpTime->wType);
	dprintf_mciwave(stddeb,"wodGetPosition // wBitsPerSample=%u\n",
			WOutDev[wDevID].Format.wBitsPerSample); 
	dprintf_mciwave(stddeb,"wodGetPosition // nSamplesPerSec=%lu\n",
			WOutDev[wDevID].Format.wf.nSamplesPerSec); 
	dprintf_mciwave(stddeb,"wodGetPosition // nChannels=%u\n",
			WOutDev[wDevID].Format.wf.nChannels); 
	dprintf_mciwave(stddeb,"wodGetPosition // nAvgBytesPerSec=%lu\n",
			WOutDev[wDevID].Format.wf.nAvgBytesPerSec); 
	switch(lpTime->wType) {
	case TIME_BYTES:
		lpTime->u.cb = WOutDev[wDevID].dwTotalPlayed;
		dprintf_mciwave(stddeb,"wodGetPosition // TIME_BYTES=%lu\n", lpTime->u.cb);
		break;
	case TIME_SAMPLES:
		dprintf_mciwave(stddeb,"wodGetPosition // dwTotalPlayed=%lu\n", 
				WOutDev[wDevID].dwTotalPlayed);
		dprintf_mciwave(stddeb,"wodGetPosition // wBitsPerSample=%u\n", 
				WOutDev[wDevID].Format.wBitsPerSample);
		lpTime->u.sample = WOutDev[wDevID].dwTotalPlayed * 8 /
					WOutDev[wDevID].Format.wBitsPerSample;
		dprintf_mciwave(stddeb,"wodGetPosition // TIME_SAMPLES=%lu\n", lpTime->u.sample);
		break;
	case TIME_SMPTE:
		time = WOutDev[wDevID].dwTotalPlayed /
			(WOutDev[wDevID].Format.wf.nAvgBytesPerSec / 1000);
		lpTime->u.smpte.hour = time / 108000;
		time -= lpTime->u.smpte.hour * 108000;
		lpTime->u.smpte.min = time / 1800;
		time -= lpTime->u.smpte.min * 1800;
		lpTime->u.smpte.sec = time / 30;
		time -= lpTime->u.smpte.sec * 30;
		lpTime->u.smpte.frame = time;
		lpTime->u.smpte.fps = 30;
		dprintf_mciwave(stddeb,
		  "wodGetPosition // TIME_SMPTE=%02u:%02u:%02u:%02u\n",
		  lpTime->u.smpte.hour, lpTime->u.smpte.min,
		  lpTime->u.smpte.sec, lpTime->u.smpte.frame);
		break;
	default:
		dprintf_mciwave(stddeb,"wodGetPosition() format not supported ! use TIME_MS !\n");
		lpTime->wType = TIME_MS;
	case TIME_MS:
		lpTime->u.ms = WOutDev[wDevID].dwTotalPlayed /
				(WOutDev[wDevID].Format.wf.nAvgBytesPerSec / 1000);
		dprintf_mciwave(stddeb,"wodGetPosition // TIME_MS=%lu\n", lpTime->u.ms);
		break;
	}
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				wodGetVolume			[internal]
 */
static DWORD wodGetVolume(WORD wDevID, LPDWORD lpdwVol)
{
	int 	mixer;
	int		volume, left, right;
	dprintf_mciwave(stddeb,"wodGetVolume(%u, %p);\n", wDevID, lpdwVol);
	if (lpdwVol == NULL) return MMSYSERR_NOTENABLED;
	if ((mixer = open(MIXER_DEV, O_RDONLY)) < 0) {
		dprintf_mciwave(stddeb, "Linux 'wodGetVolume' // mixer device not available !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (ioctl(mixer, SOUND_MIXER_READ_PCM, &volume) == -1) {
		dprintf_mciwave(stddeb,"Linux 'wodGetVolume' // unable read mixer !\n");
		return MMSYSERR_NOTENABLED;
	}
	close(mixer);
	left = volume & 0x7F;
	right = (volume >> 8) & 0x7F;
	dprintf_mciwave(stddeb,"Linux 'wodGetVolume' // left=%d right=%d !\n", left, right);
	*lpdwVol = MAKELONG(left << 9, right << 9);
	return MMSYSERR_NOERROR;
}


/**************************************************************************
 * 				wodSetVolume			[internal]
 */
static DWORD wodSetVolume(WORD wDevID, DWORD dwParam)
{
	int 	mixer;
	int		volume;
	dprintf_mciwave(stddeb,"wodSetVolume(%u, %08lX);\n", wDevID, dwParam);
	volume = (LOWORD(dwParam) >> 9 & 0x7F) + 
		((HIWORD(dwParam) >> 9  & 0x7F) << 8);
	if ((mixer = open(MIXER_DEV, O_WRONLY)) < 0) {
		dprintf_mciwave(stddeb,	"Linux 'wodSetVolume' // mixer device not available !\n");
		return MMSYSERR_NOTENABLED;
		}
    if (ioctl(mixer, SOUND_MIXER_WRITE_PCM, &volume) == -1) {
		dprintf_mciwave(stddeb,"Linux 'wodSetVolume' // unable set mixer !\n");
		return MMSYSERR_NOTENABLED;
		}
	close(mixer);
	return MMSYSERR_NOERROR;
}

#endif /* linux || __FreeBSD__*/

/**************************************************************************
 * 				wodMessage			[sample driver]
 */
DWORD wodMessage(WORD wDevID, WORD wMsg, DWORD dwUser, 
					DWORD dwParam1, DWORD dwParam2)
{
	dprintf_mciwave(stddeb,"wodMessage(%u, %04X, %08lX, %08lX, %08lX);\n",
			wDevID, wMsg, dwUser, dwParam1, dwParam2);
#if defined(linux) || defined(__FreeBSD__)
        switch(wMsg) {
	case WODM_OPEN:
		return wodOpen(wDevID, (LPWAVEOPENDESC)dwParam1, dwParam2);
	case WODM_CLOSE:
		return wodClose(wDevID);
	case WODM_WRITE:
		return wodWrite(wDevID, (LPWAVEHDR)dwParam1, dwParam2);
	case WODM_PAUSE:
		return MMSYSERR_NOTSUPPORTED;
	case WODM_STOP:
		return MMSYSERR_NOTSUPPORTED;
	case WODM_GETPOS:
		return wodGetPosition(wDevID, (LPMMTIME16)dwParam1, dwParam2);
	case WODM_BREAKLOOP:
		return MMSYSERR_NOTSUPPORTED;
	case WODM_PREPARE:
		return wodPrepare(wDevID, (LPWAVEHDR)dwParam1, dwParam2);
	case WODM_UNPREPARE:
		return wodUnprepare(wDevID, (LPWAVEHDR)dwParam1, dwParam2);
	case WODM_GETDEVCAPS:
		return wodGetDevCaps(wDevID,(LPWAVEOUTCAPS16)dwParam1,dwParam2);
	case WODM_GETNUMDEVS:
		return 1L;
	case WODM_GETPITCH:
		return MMSYSERR_NOTSUPPORTED;
	case WODM_SETPITCH:
		return MMSYSERR_NOTSUPPORTED;
	case WODM_GETPLAYBACKRATE:
		return MMSYSERR_NOTSUPPORTED;
	case WODM_SETPLAYBACKRATE:
		return MMSYSERR_NOTSUPPORTED;
	case WODM_GETVOLUME:
		return wodGetVolume(wDevID, (LPDWORD)dwParam1);
	case WODM_SETVOLUME:
		return wodSetVolume(wDevID, dwParam1);
	case WODM_RESTART:
		return wodRestart(wDevID);
	case WODM_RESET:
		return wodReset(wDevID);
	default:
		dprintf_mciwave(stddeb,"wodMessage // unknown message !\n");
	}
	return MMSYSERR_NOTSUPPORTED;
#else
	return MMSYSERR_NOTENABLED;
#endif
}


/*-----------------------------------------------------------------------*/

#if defined(linux) || defined(__FreeBSD__)

/**************************************************************************
 * 			widGetDevCaps				[internal]
 */
static DWORD widGetDevCaps(WORD wDevID, LPWAVEINCAPS16 lpCaps, DWORD dwSize)
{
	int 	audio,smplrate,samplesize=16,dsp_stereo=1,bytespersmpl;

	dprintf_mciwave(stddeb,
		"widGetDevCaps(%u, %p, %lu);\n", wDevID, lpCaps, dwSize);
	if (lpCaps == NULL) return MMSYSERR_NOTENABLED;
	if (access(SOUND_DEV,0) != 0) return MMSYSERR_NOTENABLED;
	audio = open (SOUND_DEV, O_RDONLY, 0);
	if (audio == -1) return MMSYSERR_ALLOCATED ;
#ifdef EMULATE_SB16
	lpCaps->wMid = 0x0002;
	lpCaps->wPid = 0x0004;
	strcpy(lpCaps->szPname, "SB16 Wave In");
#else
	lpCaps->wMid = 0x00FF; 	/* Manufac ID */
	lpCaps->wPid = 0x0001; 	/* Product ID */
	strcpy(lpCaps->szPname, "Linux WAVIN Driver");
#endif
	lpCaps->dwFormats = 0x00000000;
	lpCaps->wChannels = (IOCTL(audio, SNDCTL_DSP_STEREO, dsp_stereo) != 0) ? 1 : 2;
	bytespersmpl = (IOCTL(audio, SNDCTL_DSP_SAMPLESIZE, samplesize) != 0) ? 1 : 2;
	smplrate = 44100;
	if (IOCTL(audio, SNDCTL_DSP_SPEED, smplrate) == 0) {
		lpCaps->dwFormats |= WAVE_FORMAT_4M08;
		if (lpCaps->wChannels > 1)
			lpCaps->dwFormats |= WAVE_FORMAT_4S08;
		if (bytespersmpl > 1) {
			lpCaps->dwFormats |= WAVE_FORMAT_4M16;
			if (lpCaps->wChannels > 1)
				lpCaps->dwFormats |= WAVE_FORMAT_4S16;
		}
	}
	smplrate = 22050;
	if (IOCTL(audio, SNDCTL_DSP_SPEED, smplrate) == 0) {
		lpCaps->dwFormats |= WAVE_FORMAT_2M08;
		if (lpCaps->wChannels > 1)
			lpCaps->dwFormats |= WAVE_FORMAT_2S08;
		if (bytespersmpl > 1) {
			lpCaps->dwFormats |= WAVE_FORMAT_2M16;
			if (lpCaps->wChannels > 1)
				lpCaps->dwFormats |= WAVE_FORMAT_2S16;
		}
	}
	smplrate = 11025;
	if (IOCTL(audio, SNDCTL_DSP_SPEED, smplrate) == 0) {
		lpCaps->dwFormats |= WAVE_FORMAT_1M08;
		if (lpCaps->wChannels > 1)
			lpCaps->dwFormats |= WAVE_FORMAT_1S08;
		if (bytespersmpl > 1) {
			lpCaps->dwFormats |= WAVE_FORMAT_1M16;
			if (lpCaps->wChannels > 1)
				lpCaps->dwFormats |= WAVE_FORMAT_1S16;
		}
	}
	close(audio);
	dprintf_mciwave(stddeb,
		"widGetDevCaps // dwFormats = %08lX\n", lpCaps->dwFormats);
	return MMSYSERR_NOERROR;
}


/**************************************************************************
 * 				widOpen				[internal]
 */
static DWORD widOpen(WORD wDevID, LPWAVEOPENDESC lpDesc, DWORD dwFlags)
{
	int 		audio,abuf_size,smplrate,samplesize,dsp_stereo;
	LPWAVEFORMAT	lpFormat;

	dprintf_mciwave(stddeb, "widOpen(%u, %p, %08lX);\n", wDevID, lpDesc, dwFlags);
	if (lpDesc == NULL) {
		dprintf_mciwave(stddeb,"Linux 'widOpen' // Invalid Parameter !\n");
		return MMSYSERR_INVALPARAM;
	}
	if (wDevID >= MAX_WAVINDRV) {
		dprintf_mciwave(stddeb,"Linux 'widOpen' // MAX_WAVINDRV reached !\n");
		return MMSYSERR_ALLOCATED;
	}
	WInDev[wDevID].unixdev = 0;
	if (access(SOUND_DEV,0) != 0) return MMSYSERR_NOTENABLED;
	audio = open (SOUND_DEV, O_RDONLY, 0);
	if (audio == -1) {
		dprintf_mciwave(stddeb,"Linux 'widOpen' // can't open !\n");
		return MMSYSERR_ALLOCATED;
	}
	IOCTL(audio, SNDCTL_DSP_GETBLKSIZE, abuf_size);
	if (abuf_size < 1024 || abuf_size > 65536) {
		if (abuf_size == -1)
			dprintf_mciwave(stddeb,"Linux 'widOpen' // IOCTL can't 'SNDCTL_DSP_GETBLKSIZE' !\n");
		else
			dprintf_mciwave(stddeb,"Linux 'widOpen' // SNDCTL_DSP_GETBLKSIZE Invalid bufsize !\n");
		return MMSYSERR_NOTENABLED;
	}
	WInDev[wDevID].wFlags = HIWORD(dwFlags & CALLBACK_TYPEMASK);
	switch(WInDev[wDevID].wFlags) {
	case DCB_NULL:
		dprintf_mciwave(stddeb,"Linux 'widOpen' // CALLBACK_NULL!\n");
		break;
	case DCB_WINDOW:
		dprintf_mciwave(stddeb,"Linux 'widOpen' // CALLBACK_WINDOW!\n");
		break;
	case DCB_TASK:
		dprintf_mciwave(stddeb,"Linux 'widOpen' // CALLBACK_TASK!\n");
		break;
	case DCB_FUNCTION:
		dprintf_mciwave(stddeb,"Linux 'widOpen' // CALLBACK_FUNCTION!\n");
		break;
	}
	if (WInDev[wDevID].lpQueueHdr) {
		HeapFree(GetProcessHeap(),0,WInDev[wDevID].lpQueueHdr);
		WInDev[wDevID].lpQueueHdr = NULL;
	}
	WInDev[wDevID].unixdev = audio;
	WInDev[wDevID].bufsize = abuf_size;
	WInDev[wDevID].dwTotalRecorded = 0;
	memcpy(&WInDev[wDevID].waveDesc, lpDesc, sizeof(WAVEOPENDESC));
        lpFormat = (LPWAVEFORMAT) lpDesc->lpFormat; 
	if (lpFormat->wFormatTag != WAVE_FORMAT_PCM) {
		dprintf_mciwave(stddeb,"Linux 'widOpen' // Bad format %04X !\n",
					lpFormat->wFormatTag);
		return WAVERR_BADFORMAT;
	}
	memcpy(&WInDev[wDevID].Format, lpFormat, sizeof(PCMWAVEFORMAT));
	WInDev[wDevID].Format.wBitsPerSample = 8; /* <-------------- */
	if (WInDev[wDevID].Format.wf.nChannels == 0) return WAVERR_BADFORMAT;
	if (WInDev[wDevID].Format.wf.nSamplesPerSec == 0) return WAVERR_BADFORMAT;
	if (WInDev[wDevID].Format.wBitsPerSample == 0) {
		WInDev[wDevID].Format.wBitsPerSample = 8 *
		(WInDev[wDevID].Format.wf.nAvgBytesPerSec /
		WInDev[wDevID].Format.wf.nSamplesPerSec) /
		WInDev[wDevID].Format.wf.nChannels;
	}
	samplesize = WInDev[wDevID].Format.wBitsPerSample;
	smplrate = WInDev[wDevID].Format.wf.nSamplesPerSec;
	dsp_stereo = (WInDev[wDevID].Format.wf.nChannels > 1) ? TRUE : FALSE;
	IOCTL(audio, SNDCTL_DSP_SPEED, smplrate);
	IOCTL(audio, SNDCTL_DSP_SAMPLESIZE, samplesize);
	IOCTL(audio, SNDCTL_DSP_STEREO, dsp_stereo);
	dprintf_mciwave(stddeb,"Linux 'widOpen' // wBitsPerSample=%u !\n",
				WInDev[wDevID].Format.wBitsPerSample);
	dprintf_mciwave(stddeb,"Linux 'widOpen' // nSamplesPerSec=%lu !\n",
				WInDev[wDevID].Format.wf.nSamplesPerSec);
	dprintf_mciwave(stddeb,"Linux 'widOpen' // nChannels=%u !\n",
				WInDev[wDevID].Format.wf.nChannels);
	dprintf_mciwave(stddeb,"Linux 'widOpen' // nAvgBytesPerSec=%lu\n",
			WInDev[wDevID].Format.wf.nAvgBytesPerSec); 
	if (WAVE_NotifyClient(wDevID, WIM_OPEN, 0L, 0L) != MMSYSERR_NOERROR) {
		dprintf_mciwave(stddeb,"Linux 'widOpen' // can't notify client !\n");
		return MMSYSERR_INVALPARAM;
	}
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				widClose			[internal]
 */
static DWORD widClose(WORD wDevID)
{
	dprintf_mciwave(stddeb,"widClose(%u);\n", wDevID);
	if (wDevID > MAX_WAVINDRV) return MMSYSERR_INVALPARAM;
	if (WInDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'widClose' // can't close !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (WInDev[wDevID].lpQueueHdr != NULL) {
	        dprintf_mciwave(stddeb,"linux 'widclose' // still buffers open !\n");
		return WAVERR_STILLPLAYING;
	}
	close(WInDev[wDevID].unixdev);
	WInDev[wDevID].unixdev = 0;
	WInDev[wDevID].bufsize = 0;
	if (WAVE_NotifyClient(wDevID, WIM_CLOSE, 0L, 0L) != MMSYSERR_NOERROR) {
		dprintf_mciwave(stddeb,"Linux 'widClose' // can't notify client !\n");
		return MMSYSERR_INVALPARAM;
	}
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				widAddBuffer		[internal]
 */
static DWORD widAddBuffer(WORD wDevID, LPWAVEHDR lpWaveHdr, DWORD dwSize)
{
	int		count	= 1;
	LPWAVEHDR 	lpWIHdr;

	dprintf_mciwave(stddeb,
		"widAddBuffer(%u, %p, %08lX);\n", wDevID, lpWaveHdr, dwSize);
	if (WInDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'widAddBuffer' // can't do it !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (!(lpWaveHdr->dwFlags & WHDR_PREPARED)) {
		dprintf_mciwave(stddeb,	"Linux 'widAddBuffer' // never been prepared !\n");
		return WAVERR_UNPREPARED;
	}
	if (lpWaveHdr->dwFlags & WHDR_INQUEUE) {
		dprintf_mciwave(stddeb,	"Linux 'widAddBuffer' // header already in use !\n");
		return WAVERR_STILLPLAYING;
	}
	lpWaveHdr->dwFlags |= WHDR_PREPARED;
	lpWaveHdr->dwFlags |= WHDR_INQUEUE;
	lpWaveHdr->dwFlags &= ~WHDR_DONE;
	lpWaveHdr->dwBytesRecorded = 0;
	if (WInDev[wDevID].lpQueueHdr == NULL) {
		WInDev[wDevID].lpQueueHdr = lpWaveHdr;
	} else {
		lpWIHdr = WInDev[wDevID].lpQueueHdr;
		while (lpWIHdr->lpNext != NULL) {
			lpWIHdr = lpWIHdr->lpNext;
			count++;
		}
		lpWIHdr->lpNext = lpWaveHdr;
		lpWaveHdr->lpNext = NULL;
		count++;
	}
	dprintf_mciwave(stddeb,
		"widAddBuffer // buffer added ! (now %u in queue)\n", count);
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				widPrepare			[internal]
 */
static DWORD widPrepare(WORD wDevID, LPWAVEHDR lpWaveHdr, DWORD dwSize)
{
	dprintf_mciwave(stddeb,
		"widPrepare(%u, %p, %08lX);\n", wDevID, lpWaveHdr, dwSize);
	if (WInDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'widPrepare' // can't prepare !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (lpWaveHdr->dwFlags & WHDR_INQUEUE)
		return WAVERR_STILLPLAYING;
	lpWaveHdr->dwFlags |= WHDR_PREPARED;
	lpWaveHdr->dwFlags &= ~WHDR_INQUEUE;
	lpWaveHdr->dwFlags &= ~WHDR_DONE;
	lpWaveHdr->dwBytesRecorded = 0;
	dprintf_mciwave(stddeb,"Linux 'widPrepare' // header prepared !\n");
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				widUnprepare			[internal]
 */
static DWORD widUnprepare(WORD wDevID, LPWAVEHDR lpWaveHdr, DWORD dwSize)
{
	dprintf_mciwave(stddeb,
		"widUnprepare(%u, %p, %08lX);\n", wDevID, lpWaveHdr, dwSize);
	if (WInDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'widUnprepare' // can't unprepare !\n");
		return MMSYSERR_NOTENABLED;
	}
	lpWaveHdr->dwFlags &= ~WHDR_PREPARED;
	lpWaveHdr->dwFlags &= ~WHDR_INQUEUE;
	lpWaveHdr->dwFlags |= WHDR_DONE;

	dprintf_mciwave(stddeb, "Linux 'widUnprepare' // all headers unprepared !\n");
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 			widStart				[internal]
 */
static DWORD widStart(WORD wDevID)
{
	int		count	= 1;
	int             bytesRead;
	LPWAVEHDR 	lpWIHdr;
	LPWAVEHDR	*lpWaveHdr;

	dprintf_mciwave(stddeb,"widStart(%u);\n", wDevID);
	if (WInDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,	"Linux 'widStart' // can't start recording !\n");
		return MMSYSERR_NOTENABLED;
	}

	lpWaveHdr = &(WInDev[wDevID].lpQueueHdr);
	dprintf_mciwave(stddeb,"Linux 'widstart'// lpWaveHdr = %08lx\n",(DWORD)lpWaveHdr);
	if (!*lpWaveHdr || !(*lpWaveHdr)->lpData) {
		dprintf_mciwave(stddeb,"Linux 'widStart' // never been prepared !\n");
		return WAVERR_UNPREPARED;
	}

	while(*lpWaveHdr != NULL) {
	        lpWIHdr = *lpWaveHdr;
		dprintf_mciwave(stddeb,
			"widStart // recording buf#%u=%p size=%lu \n",
			count, lpWIHdr->lpData, lpWIHdr->dwBufferLength);
		fflush(stddeb);
		bytesRead = read (WInDev[wDevID].unixdev, 
			lpWIHdr->lpData,
			lpWIHdr->dwBufferLength);
		if (bytesRead==-1)
			perror("read from audio device");
		fprintf(stderr,"bytesread = %d (%ld)\n",bytesRead,lpWIHdr->dwBufferLength);
		lpWIHdr->dwBytesRecorded = bytesRead;
		WInDev[wDevID].dwTotalRecorded += lpWIHdr->dwBytesRecorded;
		lpWIHdr->dwFlags &= ~WHDR_INQUEUE;
		lpWIHdr->dwFlags |= WHDR_DONE;

		/* FIXME: should pass segmented pointer here, do we need that?*/
		if (WAVE_NotifyClient(wDevID, WIM_DATA, (DWORD)lpWaveHdr, lpWIHdr->dwBytesRecorded) != MMSYSERR_NOERROR) {
			dprintf_mciwave(stddeb,	"Linux 'widStart' // can't notify client !\n");
			return MMSYSERR_INVALPARAM;
		}
		/* removes the current block from the queue */
		*lpWaveHdr = lpWIHdr->lpNext;
		count++;
	}
	dprintf_mciwave(stddeb,"widStart // end of recording !\n");
	fflush(stddeb);
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 			widStop					[internal]
 */
static DWORD widStop(WORD wDevID)
{
	dprintf_mciwave(stddeb,"widStop(%u);\n", wDevID);
	if (WInDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'widStop' // can't stop !\n");
		return MMSYSERR_NOTENABLED;
	}
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 			widReset				[internal]
 */
static DWORD widReset(WORD wDevID)
{
	dprintf_mciwave(stddeb,"widReset(%u);\n", wDevID);
	if (WInDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'widReset' // can't reset !\n");
		return MMSYSERR_NOTENABLED;
	}
	return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				widGetPosition			[internal]
 */
static DWORD widGetPosition(WORD wDevID, LPMMTIME16 lpTime, DWORD uSize)
{
	int		time;
    
	dprintf_mciwave(stddeb,
		"widGetPosition(%u, %p, %lu);\n", wDevID, lpTime, uSize);
	if (WInDev[wDevID].unixdev == 0) {
		dprintf_mciwave(stddeb,"Linux 'widGetPosition' // can't get pos !\n");
		return MMSYSERR_NOTENABLED;
	}
	if (lpTime == NULL)	return MMSYSERR_INVALPARAM;
	dprintf_mciwave(stddeb,"widGetPosition // wType=%04X !\n", 
			lpTime->wType);
	dprintf_mciwave(stddeb,"widGetPosition // wBitsPerSample=%u\n",
			WInDev[wDevID].Format.wBitsPerSample); 
	dprintf_mciwave(stddeb,"widGetPosition // nSamplesPerSec=%lu\n",
			WInDev[wDevID].Format.wf.nSamplesPerSec); 
	dprintf_mciwave(stddeb,"widGetPosition // nChannels=%u\n",
			WInDev[wDevID].Format.wf.nChannels); 
	dprintf_mciwave(stddeb,"widGetPosition // nAvgBytesPerSec=%lu\n",
			WInDev[wDevID].Format.wf.nAvgBytesPerSec); 
	fflush(stddeb);
	switch(lpTime->wType) {
	case TIME_BYTES:
		lpTime->u.cb = WInDev[wDevID].dwTotalRecorded;
		dprintf_mciwave(stddeb,
		    "widGetPosition // TIME_BYTES=%lu\n", lpTime->u.cb);
		break;
	case TIME_SAMPLES:
		lpTime->u.sample = WInDev[wDevID].dwTotalRecorded * 8 /
				  WInDev[wDevID].Format.wBitsPerSample;
		dprintf_mciwave(stddeb,
				"widGetPosition // TIME_SAMPLES=%lu\n", 
				lpTime->u.sample);
		break;
	case TIME_SMPTE:
		time = WInDev[wDevID].dwTotalRecorded /
			(WInDev[wDevID].Format.wf.nAvgBytesPerSec / 1000);
		lpTime->u.smpte.hour = time / 108000;
		time -= lpTime->u.smpte.hour * 108000;
		lpTime->u.smpte.min = time / 1800;
		time -= lpTime->u.smpte.min * 1800;
		lpTime->u.smpte.sec = time / 30;
		time -= lpTime->u.smpte.sec * 30;
		lpTime->u.smpte.frame = time;
		lpTime->u.smpte.fps = 30;
dprintf_mciwave(stddeb,"widGetPosition // TIME_SMPTE=%02u:%02u:%02u:%02u\n",
				lpTime->u.smpte.hour, lpTime->u.smpte.min,
				lpTime->u.smpte.sec, lpTime->u.smpte.frame);
		break;
	default:
		dprintf_mciwave(stddeb,"widGetPosition() format not supported ! use TIME_MS !\n");
		lpTime->wType = TIME_MS;
	case TIME_MS:
		lpTime->u.ms = WInDev[wDevID].dwTotalRecorded /
				(WInDev[wDevID].Format.wf.nAvgBytesPerSec / 1000);
		dprintf_mciwave(stddeb,
		      "widGetPosition // TIME_MS=%lu\n", lpTime->u.ms);
		break;
	}
	return MMSYSERR_NOERROR;
}

#endif /* linux || __FreeBSD__ */

/**************************************************************************
 * 				widMessage			[sample driver]
 */
DWORD widMessage(WORD wDevID, WORD wMsg, DWORD dwUser, 
					DWORD dwParam1, DWORD dwParam2)
{
	dprintf_mciwave(stddeb,"widMessage(%u, %04X, %08lX, %08lX, %08lX);\n",
			wDevID, wMsg, dwUser, dwParam1, dwParam2);
#if defined(linux) || defined(__FreeBSD__)
	switch(wMsg) {
	case WIDM_OPEN:
		return widOpen(wDevID, (LPWAVEOPENDESC)dwParam1, dwParam2);
	case WIDM_CLOSE:
		return widClose(wDevID);
	case WIDM_ADDBUFFER:
		return widAddBuffer(wDevID, (LPWAVEHDR)dwParam1, dwParam2);
	case WIDM_PREPARE:
		return widPrepare(wDevID, (LPWAVEHDR)dwParam1, dwParam2);
	case WIDM_UNPREPARE:
		return widUnprepare(wDevID, (LPWAVEHDR)dwParam1, dwParam2);
	case WIDM_GETDEVCAPS:
		return widGetDevCaps(wDevID, (LPWAVEINCAPS16)dwParam1,dwParam2);
	case WIDM_GETNUMDEVS:
		return 1;
	case WIDM_GETPOS:
		return widGetPosition(wDevID, (LPMMTIME16)dwParam1, dwParam2);
	case WIDM_RESET:
		return widReset(wDevID);
	case WIDM_START:
		return widStart(wDevID);
	case WIDM_PAUSE:
		return widStop(wDevID);
	case WIDM_STOP:
		return widStop(wDevID);
	default:
		dprintf_mciwave(stddeb,"widMessage // unknown message !\n");
	}
	return MMSYSERR_NOTSUPPORTED;
#else
	return MMSYSERR_NOTENABLED;
#endif
}


/**************************************************************************
 * 				AUDIO_DriverProc		[sample driver]
 */
LONG WAVE_DriverProc(DWORD dwDevID, HDRVR16 hDriv, WORD wMsg, 
						DWORD dwParam1, DWORD dwParam2)
{
#if defined(linux) || defined(__FreeBSD__)
	dprintf_mciwave(stddeb,"WAVE_DriverProc(%08lX, %04X, %04X, %08lX, %08lX)\n", 
		dwDevID, hDriv, wMsg, dwParam1, dwParam2);
	switch(wMsg) {
	case DRV_LOAD:
		return 1;
	case DRV_FREE:
		return 1;
	case DRV_OPEN:
		return 1;
	case DRV_CLOSE:
		return 1;
	case DRV_ENABLE:
		return 1;
	case DRV_DISABLE:
		return 1;
	case DRV_QUERYCONFIGURE:
		return 1;
	case DRV_CONFIGURE:
		MessageBox16(0, "Sample MultiMedia Linux Driver !", 
							"MMLinux Driver", MB_OK);
		return 1;
	case DRV_INSTALL:
		return DRVCNF_RESTART;
	case DRV_REMOVE:
		return DRVCNF_RESTART;
	case MCI_OPEN_DRIVER:
	case MCI_OPEN:
		return WAVE_mciOpen(dwDevID, dwParam1, (LPMCI_WAVE_OPEN_PARMS16)PTR_SEG_TO_LIN(dwParam2));
	case MCI_CUE:
		return WAVE_mciCue(dwDevID, dwParam1, (LPMCI_GENERIC_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_CLOSE_DRIVER:
	case MCI_CLOSE:
		return WAVE_mciClose(dwDevID, dwParam1, (LPMCI_GENERIC_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_PLAY:
		return WAVE_mciPlay(dwDevID, dwParam1, (LPMCI_PLAY_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_RECORD:
		return WAVE_mciRecord(dwDevID, dwParam1, (LPMCI_RECORD_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_STOP:
		return WAVE_mciStop(dwDevID, dwParam1, (LPMCI_GENERIC_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_SET:
		return WAVE_mciSet(dwDevID, dwParam1, (LPMCI_SET_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_PAUSE:
		return WAVE_mciPause(dwDevID, dwParam1, (LPMCI_GENERIC_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_RESUME:
		return WAVE_mciResume(dwDevID, dwParam1, (LPMCI_GENERIC_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_STATUS:
		return WAVE_mciStatus(dwDevID, dwParam1, (LPMCI_STATUS_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_GETDEVCAPS:
		return WAVE_mciGetDevCaps(dwDevID, dwParam1, (LPMCI_GETDEVCAPS_PARMS)PTR_SEG_TO_LIN(dwParam2));
	case MCI_INFO:
		return WAVE_mciInfo(dwDevID, dwParam1, (LPMCI_INFO_PARMS16)PTR_SEG_TO_LIN(dwParam2));

	case MCI_LOAD:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_SAVE:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_SEEK:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_FREEZE:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_PUT:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_REALIZE:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_UNFREEZE:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_UPDATE:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_WHERE:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_WINDOW:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_STEP:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_SPIN:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_ESCAPE:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_COPY:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_CUT:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_DELETE:
		return MMSYSERR_NOTSUPPORTED;
	case MCI_PASTE:
		return MMSYSERR_NOTSUPPORTED;

	default:
		return DefDriverProc(dwDevID, hDriv, wMsg, dwParam1, dwParam2);
	}
#else
	return MMSYSERR_NOTENABLED;
#endif
}
