/*
 * Copyright 1993 Robert J. Amstadt
 * Copyright 1995 Martin von Loewis
 * Copyright 1995, 1996, 1997 Alexandre Julliard
 * Copyright 1997 Eric Youngdale
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "windows.h"
#include "winnt.h"
#include "module.h"
#include "neexe.h"
#include "selectors.h"
#include "stackframe.h"

#ifdef NEED_UNDERSCORE_PREFIX
# define PREFIX "_"
#else
# define PREFIX
#endif

#if defined(__GNUC__) && !defined(__svr4__)
# define USE_STABS
#else
# undef USE_STABS
#endif

typedef enum
{
    TYPE_INVALID,
    TYPE_BYTE,         /* byte variable (Win16) */
    TYPE_WORD,         /* word variable (Win16) */
    TYPE_LONG,         /* long variable (Win16) */
    TYPE_PASCAL_16,    /* pascal function with 16-bit return (Win16) */
    TYPE_PASCAL,       /* pascal function with 32-bit return (Win16) */
    TYPE_ABS,          /* absolute value (Win16) */
    TYPE_RETURN,       /* simple return value function (Win16) */
    TYPE_REGISTER,     /* register function */
    TYPE_STUB,         /* unimplemented stub */
    TYPE_STDCALL,      /* stdcall function (Win32) */
    TYPE_CDECL,        /* cdecl function (Win32) */
    TYPE_VARARGS,      /* varargs function (Win32) */
    TYPE_EXTERN,       /* external symbol (Win32) */
    TYPE_NBTYPES
} ORD_TYPE;

static const char * const TypeNames[TYPE_NBTYPES] =
{
    NULL,
    "byte",         /* TYPE_BYTE */
    "word",         /* TYPE_WORD */
    "long",         /* TYPE_LONG */
    "pascal16",     /* TYPE_PASCAL_16 */
    "pascal",       /* TYPE_PASCAL */
    "equate",       /* TYPE_ABS */
    "return",       /* TYPE_RETURN */
    "register",     /* TYPE_REGISTER */
    "stub",         /* TYPE_STUB */
    "stdcall",      /* TYPE_STDCALL */
    "cdecl",        /* TYPE_CDECL */
    "varargs",      /* TYPE_VARARGS */
    "extern"        /* TYPE_EXTERN */
};

#define MAX_ORDINALS	1299

  /* Callback function used for stub functions */
#define STUB_CALLBACK \
  ((SpecType == SPEC_WIN16) ? "RELAY_Unimplemented16": "RELAY_Unimplemented32")

typedef enum
{
    SPEC_INVALID,
    SPEC_WIN16,
    SPEC_WIN32
} SPEC_TYPE;

typedef struct
{
    int n_values;
    int *values;
} ORD_VARIABLE;

typedef struct
{
    int  n_args;
    char arg_types[32];
    char link_name[80];
} ORD_FUNCTION;

typedef struct
{
    int arg_size;
    int ret_value;
} ORD_RETURN;

typedef struct
{
    int value;
} ORD_ABS;

typedef struct
{
    char link_name[80];
} ORD_VARARGS;

typedef struct
{
    char link_name[80];
} ORD_EXTERN;

typedef struct
{
    ORD_TYPE    type;
    int         offset;
    int		lineno;
    char        name[80];
    union
    {
        ORD_VARIABLE   var;
        ORD_FUNCTION   func;
        ORD_RETURN     ret;
        ORD_ABS        abs;
        ORD_VARARGS    vargs;
        ORD_EXTERN     ext;
    } u;
} ORDDEF;

static ORDDEF OrdinalDefinitions[MAX_ORDINALS];

static SPEC_TYPE SpecType = SPEC_INVALID;
static char DLLName[80];
static char DLLFileName[80];
int Limit = 0;
int Base = MAX_ORDINALS;
int DLLHeapSize = 0;
char *SpecName;
FILE *SpecFp;

char *ParseBuffer = NULL;
char *ParseNext;
char ParseSaveChar;
int Line;

static int debugging = 1;

  /* Offset of a structure field relative to the start of the struct */
#define STRUCTOFFSET(type,field) ((int)&((type *)0)->field)

  /* Offset of register relative to the start of the CONTEXT struct */
#define CONTEXTOFFSET(reg)  STRUCTOFFSET(CONTEXT,reg)

static void *xmalloc (size_t size)
{
    void *res;

    res = malloc (size ? size : 1);
    if (res == NULL)
    {
        fprintf (stderr, "Virtual memory exhausted.\n");
        exit (1);
    }
    return res;
}


static void *xrealloc (void *ptr, size_t size)
{
    void *res = realloc (ptr, size);
    if (res == NULL)
    {
        fprintf (stderr, "Virtual memory exhausted.\n");
        exit (1);
    }
    return res;
}


static int IsNumberString(char *s)
{
    while (*s != '\0')
	if (!isdigit(*s++))
	    return 0;

    return 1;
}

static char *strupper(char *s)
{
    char *p;
    
    for(p = s; *p != '\0'; p++)
	*p = toupper(*p);

    return s;
}

static char * GetTokenInLine(void)
{
    char *p;
    char *token;

    if (ParseNext != ParseBuffer)
    {
	if (ParseSaveChar == '\0')
	    return NULL;
	*ParseNext = ParseSaveChar;
    }
    
    /*
     * Remove initial white space.
     */
    for (p = ParseNext; isspace(*p); p++)
	;
    
    if ((*p == '\0') || (*p == '#'))
	return NULL;
    
    /*
     * Find end of token.
     */
    token = p++;
    if (*token != '(' && *token != ')')
	while (*p != '\0' && *p != '(' && *p != ')' && !isspace(*p))
	    p++;
    
    ParseSaveChar = *p;
    ParseNext = p;
    *p = '\0';

    return token;
}

static char * GetToken(void)
{
    char *token;

    if (ParseBuffer == NULL)
    {
	ParseBuffer = xmalloc(512);
	ParseNext = ParseBuffer;
	while (1)
	{
            Line++;
	    if (fgets(ParseBuffer, 511, SpecFp) == NULL)
		return NULL;
	    if (ParseBuffer[0] != '#')
		break;
	}
    }

    while ((token = GetTokenInLine()) == NULL)
    {
	ParseNext = ParseBuffer;
	while (1)
	{
            Line++;
	    if (fgets(ParseBuffer, 511, SpecFp) == NULL)
		return NULL;
	    if (ParseBuffer[0] != '#')
		break;
	}
    }

    return token;
}


/*******************************************************************
 *         ParseVariable
 *
 * Parse a variable definition.
 */
static int ParseVariable( ORDDEF *odp )
{
    char *endptr;
    int *value_array;
    int n_values;
    int value_array_size;
    
    char *token = GetToken();
    if (*token != '(')
    {
	fprintf(stderr, "%s:%d: Expected '(' got '%s'\n",
                SpecName, Line, token);
	return -1;
    }

    n_values = 0;
    value_array_size = 25;
    value_array = xmalloc(sizeof(*value_array) * value_array_size);
    
    while ((token = GetToken()) != NULL)
    {
	if (*token == ')')
	    break;

	value_array[n_values++] = strtol(token, &endptr, 0);
	if (n_values == value_array_size)
	{
	    value_array_size += 25;
	    value_array = xrealloc(value_array, 
				   sizeof(*value_array) * value_array_size);
	}
	
	if (endptr == NULL || *endptr != '\0')
	{
	    fprintf(stderr, "%s:%d: Expected number value, got '%s'\n",
                    SpecName, Line, token);
	    return -1;
	}
    }
    
    if (token == NULL)
    {
	fprintf(stderr, "%s:%d: End of file in variable declaration\n",
                SpecName, Line);
	return -1;
    }

    odp->u.var.n_values = n_values;
    odp->u.var.values = xrealloc(value_array, sizeof(*value_array) * n_values);

    return 0;
}


/*******************************************************************
 *         ParseExportFunction
 *
 * Parse a function definition.
 */
static int ParseExportFunction( ORDDEF *odp )
{
    char *token;
    int i;

    switch(SpecType)
    {
    case SPEC_WIN16:
        if (odp->type == TYPE_STDCALL)
        {
            fprintf( stderr, "%s:%d: 'stdcall' not supported for Win16\n",
                     SpecName, Line );
            return -1;
        }
        if (odp->type == TYPE_CDECL)
        {
            fprintf( stderr, "%s:%d: 'cdecl' not supported for Win16\n",
                     SpecName, Line );
            return -1;
        }
        break;
    case SPEC_WIN32:
        if ((odp->type == TYPE_PASCAL) || (odp->type == TYPE_PASCAL_16))
        {
            fprintf( stderr, "%s:%d: 'pascal' not supported for Win32\n",
                     SpecName, Line );
            return -1;
        }
        break;
    default:
        break;
    }

    token = GetToken();
    if (*token != '(')
    {
	fprintf(stderr, "%s:%d: Expected '(' got '%s'\n",
                SpecName, Line, token);
	return -1;
    }

    for (i = 0; i < sizeof(odp->u.func.arg_types)-1; i++)
    {
	token = GetToken();
	if (*token == ')')
	    break;

        if (!strcmp(token, "word"))
            odp->u.func.arg_types[i] = 'w';
        else if (!strcmp(token, "s_word"))
            odp->u.func.arg_types[i] = 's';
        else if (!strcmp(token, "long") || !strcmp(token, "segptr"))
            odp->u.func.arg_types[i] = 'l';
        else if (!strcmp(token, "ptr"))
            odp->u.func.arg_types[i] = 'p';
	else if (!strcmp(token, "str"))
	    odp->u.func.arg_types[i] = 't';
	else if (!strcmp(token, "wstr"))
	    odp->u.func.arg_types[i] = 'W';
	else if (!strcmp(token, "segstr"))
	    odp->u.func.arg_types[i] = 'T';
        else if (!strcmp(token, "double"))
        {
            odp->u.func.arg_types[i++] = 'l';
            odp->u.func.arg_types[i] = 'l';
        }
        else
        {
            fprintf(stderr, "%s:%d: Unknown variable type '%s'\n",
                    SpecName, Line, token);
            return -1;
        }
        if (SpecType == SPEC_WIN32)
        {
            if (strcmp(token, "long") &&
                strcmp(token, "ptr") &&
                strcmp(token, "str") &&
                strcmp(token, "wstr") &&
                strcmp(token, "double"))
            {
                fprintf( stderr, "%s:%d: Type '%s' not supported for Win32\n",
                         SpecName, Line, token );
                return -1;
            }
        }
    }
    if ((*token != ')') || (i >= sizeof(odp->u.func.arg_types)))
    {
        fprintf( stderr, "%s:%d: Too many arguments\n", SpecName, Line );
        return -1;
    }
    odp->u.func.arg_types[i] = '\0';
    if ((odp->type == TYPE_STDCALL) && !i)
        odp->type = TYPE_CDECL; /* stdcall is the same as cdecl for 0 args */
    if ((odp->type == TYPE_REGISTER) && (SpecType == SPEC_WIN32) && i)
    {
        fprintf( stderr, "%s:%d: register functions cannot have arguments in Win32\n",
                 SpecName, Line );
        return -1;
    }
    strcpy(odp->u.func.link_name, GetToken());
    return 0;
}


/*******************************************************************
 *         ParseEquate
 *
 * Parse an 'equate' definition.
 */
static int ParseEquate( ORDDEF *odp )
{
    char *endptr;
    
    char *token = GetToken();
    int value = strtol(token, &endptr, 0);
    if (endptr == NULL || *endptr != '\0')
    {
	fprintf(stderr, "%s:%d: Expected number value, got '%s'\n",
                SpecName, Line, token);
	return -1;
    }

    if (SpecType == SPEC_WIN32)
    {
        fprintf( stderr, "%s:%d: 'equate' not supported for Win32\n",
                 SpecName, Line );
        return -1;
    }

    odp->u.abs.value = value;
    return 0;
}


/*******************************************************************
 *         ParseReturn
 *
 * Parse a 'return' definition.
 */
static int ParseReturn( ORDDEF *odp )
{
    char *token;
    char *endptr;
    
    token = GetToken();
    odp->u.ret.arg_size = strtol(token, &endptr, 0);
    if (endptr == NULL || *endptr != '\0')
    {
	fprintf(stderr, "%s:%d: Expected number value, got '%s'\n",
                SpecName, Line, token);
	return -1;
    }

    token = GetToken();
    odp->u.ret.ret_value = strtol(token, &endptr, 0);
    if (endptr == NULL || *endptr != '\0')
    {
	fprintf(stderr, "%s:%d: Expected number value, got '%s'\n",
                SpecName, Line, token);
	return -1;
    }

    if (SpecType == SPEC_WIN32)
    {
        fprintf( stderr, "%s:%d: 'return' not supported for Win32\n",
                 SpecName, Line );
        return -1;
    }

    return 0;
}


/*******************************************************************
 *         ParseStub
 *
 * Parse a 'stub' definition.
 */
static int ParseStub( ORDDEF *odp )
{
    odp->u.func.arg_types[0] = '\0';
    strcpy( odp->u.func.link_name, STUB_CALLBACK );
    return 0;
}


/*******************************************************************
 *         ParseVarargs
 *
 * Parse an 'varargs' definition.
 */
static int ParseVarargs( ORDDEF *odp )
{
    char *token;

    if (SpecType == SPEC_WIN16)
    {
        fprintf( stderr, "%s:%d: 'varargs' not supported for Win16\n",
                 SpecName, Line );
        return -1;
    }

    token = GetToken();
    if (*token != '(')
    {
	fprintf(stderr, "%s:%d: Expected '(' got '%s'\n",
                SpecName, Line, token);
	return -1;
    }
    token = GetToken();
    if (*token != ')')
    {
	fprintf(stderr, "%s:%d: Expected ')' got '%s'\n",
                SpecName, Line, token);
	return -1;
    }

    strcpy( odp->u.vargs.link_name, GetToken() );
    return 0;
}


/*******************************************************************
 *         ParseExtern
 *
 * Parse an 'extern' definition.
 */
static int ParseExtern( ORDDEF *odp )
{
    if (SpecType == SPEC_WIN16)
    {
        fprintf( stderr, "%s:%d: 'extern' not supported for Win16\n",
                 SpecName, Line );
        return -1;
    }
    strcpy( odp->u.ext.link_name, GetToken() );
    return 0;
}


/*******************************************************************
 *         ParseOrdinal
 *
 * Parse an ordinal definition.
 */
static int ParseOrdinal(int ordinal)
{
    ORDDEF *odp;
    char *token;

    if (ordinal >= MAX_ORDINALS)
    {
	fprintf(stderr, "%s:%d: Ordinal number too large\n", SpecName, Line );
	return -1;
    }
    if (ordinal > Limit) Limit = ordinal;
    if (ordinal < Base) Base = ordinal;

    odp = &OrdinalDefinitions[ordinal];
    if (!(token = GetToken()))
    {
	fprintf(stderr, "%s:%d: Expected type after ordinal\n", SpecName, Line);
	return -1;
    }

    for (odp->type = 0; odp->type < TYPE_NBTYPES; odp->type++)
        if (TypeNames[odp->type] && !strcmp( token, TypeNames[odp->type] ))
            break;

    if (odp->type >= TYPE_NBTYPES)
    {
        fprintf( stderr,
                 "%s:%d: Expected type after ordinal, found '%s' instead\n",
                 SpecName, Line, token );
        return -1;
    }

    if (!(token = GetToken()))
    {
        fprintf( stderr, "%s:%d: Expected name after type\n", SpecName, Line );
        return -1;
    }
    strcpy( odp->name, token );
    odp->lineno = Line;

    switch(odp->type)
    {
    case TYPE_BYTE:
    case TYPE_WORD:
    case TYPE_LONG:
	return ParseVariable( odp );
    case TYPE_PASCAL_16:
    case TYPE_PASCAL:
    case TYPE_REGISTER:
    case TYPE_STDCALL:
    case TYPE_CDECL:
	return ParseExportFunction( odp );
    case TYPE_ABS:
	return ParseEquate( odp );
    case TYPE_RETURN:
	return ParseReturn( odp );
    case TYPE_STUB:
	return ParseStub( odp );
    case TYPE_VARARGS:
	return ParseVarargs( odp );
    case TYPE_EXTERN:
	return ParseExtern( odp );
    default:
        fprintf( stderr, "Should not happen\n" );
        return -1;
    }
}


/*******************************************************************
 *         ParseTopLevel
 *
 * Parse a spec file.
 */
static int ParseTopLevel(void)
{
    char *token;
    
    while ((token = GetToken()) != NULL)
    {
	if (strcmp(token, "name") == 0)
	{
	    strcpy(DLLName, GetToken());
	    strupper(DLLName);
            if (!DLLFileName[0]) sprintf( DLLFileName, "%s.DLL", DLLName );
	}
	else if (strcmp(token, "file") == 0)
	{
	    strcpy(DLLFileName, GetToken());
	    strupper(DLLFileName);
	}
        else if (strcmp(token, "type") == 0)
        {
            token = GetToken();
            if (!strcmp(token, "win16" )) SpecType = SPEC_WIN16;
            else if (!strcmp(token, "win32" )) SpecType = SPEC_WIN32;
            else
            {
                fprintf(stderr, "%s:%d: Type must be 'win16' or 'win32'\n",
                        SpecName, Line);
                return -1;
            }
        }
	else if (strcmp(token, "heap") == 0)
	{
            token = GetToken();
            if (!IsNumberString(token))
            {
		fprintf(stderr, "%s:%d: Expected number after heap\n",
                        SpecName, Line);
		return -1;
            }
            DLLHeapSize = atoi(token);
	}
	else if (IsNumberString(token))
	{
	    int ordinal;
	    int rv;
	    
	    ordinal = atoi(token);
	    if ((rv = ParseOrdinal(ordinal)) < 0)
		return rv;
	}
	else
	{
	    fprintf(stderr, 
		    "%s:%d: Expected name, id, length or ordinal\n",
                    SpecName, Line);
	    return -1;
	}
    }

    return 0;
}


/*******************************************************************
 *         StoreVariableCode
 *
 * Store a list of ints into a byte array.
 */
static int StoreVariableCode( unsigned char *buffer, int size, ORDDEF *odp )
{
    int i;

    switch(size)
    {
    case 1:
        for (i = 0; i < odp->u.var.n_values; i++)
            buffer[i] = odp->u.var.values[i];
        break;
    case 2:
        for (i = 0; i < odp->u.var.n_values; i++)
            ((unsigned short *)buffer)[i] = odp->u.var.values[i];
        break;
    case 4:
        for (i = 0; i < odp->u.var.n_values; i++)
            ((unsigned int *)buffer)[i] = odp->u.var.values[i];
        break;
    }
    return odp->u.var.n_values * size;
}


/*******************************************************************
 *         DumpBytes
 *
 * Dump a byte stream into the assembly code.
 */
static void DumpBytes( FILE *outfile, const unsigned char *data, int len,
                       const char *section, const char *label_start )
{
    int i;
    if (section) fprintf( outfile, "\t%s\n", section );
    if (label_start) fprintf( outfile, "%s:\n", label_start );
    for (i = 0; i < len; i++)
    {
        if (!(i & 0x0f)) fprintf( outfile, "\t.byte " );
        fprintf( outfile, "%d", *data++ );
        if (i < len - 1)
            fprintf( outfile, "%c", ((i & 0x0f) != 0x0f) ? ',' : '\n' );
    }
    fprintf( outfile, "\n" );
}


/*******************************************************************
 *         BuildModule16
 *
 * Build the in-memory representation of a 16-bit NE module, and dump it
 * as a byte stream into the assembly code.
 */
static int BuildModule16( FILE *outfile, int max_code_offset,
                          int max_data_offset )
{
    ORDDEF *odp;
    int i;
    char *buffer;
    NE_MODULE *pModule;
    SEGTABLEENTRY *pSegment;
    OFSTRUCT *pFileInfo;
    BYTE *pstr, *bundle;
    WORD *pword;

    /*   Module layout:
     * NE_MODULE       Module
     * OFSTRUCT        File information
     * SEGTABLEENTRY   Segment 1 (code)
     * SEGTABLEENTRY   Segment 2 (data)
     * WORD[2]         Resource table (empty)
     * BYTE[2]         Imported names (empty)
     * BYTE[n]         Resident names table
     * BYTE[n]         Entry table
     */

    buffer = xmalloc( 0x10000 );

    pModule = (NE_MODULE *)buffer;
    pModule->magic = IMAGE_OS2_SIGNATURE;
    pModule->count = 1;
    pModule->next = 0;
    pModule->flags = NE_FFLAGS_SINGLEDATA | NE_FFLAGS_BUILTIN | NE_FFLAGS_LIBMODULE;
    pModule->dgroup = 2;
    pModule->heap_size = DLLHeapSize;
    pModule->stack_size = 0;
    pModule->ip = 0;
    pModule->cs = 0;
    pModule->sp = 0;
    pModule->ss = 0;
    pModule->seg_count = 2;
    pModule->modref_count = 0;
    pModule->nrname_size = 0;
    pModule->modref_table = 0;
    pModule->nrname_fpos = 0;
    pModule->moveable_entries = 0;
    pModule->alignment = 0;
    pModule->truetype = 0;
    pModule->os_flags = NE_OSFLAGS_WINDOWS;
    pModule->misc_flags = 0;
    pModule->dlls_to_init  = 0;
    pModule->nrname_handle = 0;
    pModule->min_swap_area = 0;
    pModule->expected_version = 0x030a;
    pModule->pe_module = NULL;
    pModule->self = 0;
    pModule->self_loading_sel = 0;

      /* File information */

    pFileInfo = (OFSTRUCT *)(pModule + 1);
    pModule->fileinfo = (int)pFileInfo - (int)pModule;
    memset( pFileInfo, 0, sizeof(*pFileInfo) - sizeof(pFileInfo->szPathName) );
    pFileInfo->cBytes = sizeof(*pFileInfo) - sizeof(pFileInfo->szPathName)
                        + strlen(DLLFileName);
    strcpy( pFileInfo->szPathName, DLLFileName );
    pstr = (char *)pFileInfo + pFileInfo->cBytes + 1;
        
      /* Segment table */

    pSegment = (SEGTABLEENTRY *)pstr;
    pModule->seg_table = (int)pSegment - (int)pModule;
    pSegment->filepos = 0;
    pSegment->size = max_code_offset;
    pSegment->flags = 0;
    pSegment->minsize = max_code_offset;
    pSegment->selector = 0;
    pSegment++;

    pModule->dgroup_entry = (int)pSegment - (int)pModule;
    pSegment->filepos = 0;
    pSegment->size = max_data_offset;
    pSegment->flags = NE_SEGFLAGS_DATA;
    pSegment->minsize = max_data_offset;
    pSegment->selector = 0;
    pSegment++;

      /* Resource table */

    pword = (WORD *)pSegment;
    pModule->res_table = (int)pword - (int)pModule;
    *pword++ = 0;
    *pword++ = 0;

      /* Imported names table */

    pstr = (char *)pword;
    pModule->import_table = (int)pstr - (int)pModule;
    *pstr++ = 0;
    *pstr++ = 0;

      /* Resident names table */

    pModule->name_table = (int)pstr - (int)pModule;
    /* First entry is module name */
    *pstr = strlen(DLLName );
    strcpy( pstr + 1, DLLName );
    pstr += *pstr + 1;
    *(WORD *)pstr = 0;
    pstr += sizeof(WORD);
    /* Store all ordinals */
    odp = OrdinalDefinitions + 1;
    for (i = 1; i <= Limit; i++, odp++)
    {
        if (!odp->name[0]) continue;
        *pstr = strlen( odp->name );
        strcpy( pstr + 1, odp->name );
        strupper( pstr + 1 );
        pstr += *pstr + 1;
        *(WORD *)pstr = i;
        pstr += sizeof(WORD);
    }
    *pstr++ = 0;

      /* Entry table */

    pModule->entry_table = (int)pstr - (int)pModule;
    bundle = NULL;
    odp = OrdinalDefinitions + 1;
    for (i = 1; i <= Limit; i++, odp++)
    {
        int selector = 0;

	switch (odp->type)
	{
        case TYPE_PASCAL:
        case TYPE_PASCAL_16:
        case TYPE_REGISTER:
        case TYPE_RETURN:
        case TYPE_STUB:
            selector = 1;  /* Code selector */
            break;

        case TYPE_BYTE:
        case TYPE_WORD:
        case TYPE_LONG:
            selector = 2;  /* Data selector */
            break;

        case TYPE_ABS:
            selector = 0xfe;  /* Constant selector */
            break;

        default:
            selector = 0;  /* Invalid selector */
            break;
        }

          /* create a new bundle if necessary */
        if (!bundle || (bundle[0] >= 254) || (bundle[1] != selector))
        {
            bundle = pstr;
            bundle[0] = 0;
            bundle[1] = selector;
            pstr += 2;
        }

        (*bundle)++;
        if (selector != 0)
        {
            *pstr++ = 1;
            *(WORD *)pstr = odp->offset;
            pstr += sizeof(WORD);
        }
    }
    *pstr++ = 0;

      /* Dump the module content */

    DumpBytes( outfile, (char *)pModule, (int)pstr - (int)pModule,
               ".data", "Module_Start" );
    return (int)pstr - (int)pModule;
}


/*******************************************************************
 *         BuildSpec32File
 *
 * Build a Win32 assembly file from a spec file.
 */
static int BuildSpec32File( char * specfile, FILE *outfile )
{
    ORDDEF *odp;
    int i, nb_names, nb_stubs;
    char buffer[1024];
    unsigned char *args, *p;

    fprintf( outfile, "/* File generated automatically; do not edit! */\n" );
    fprintf( outfile, "\t.file\t\"%s\"\n", specfile );
#ifdef USE_STABS
    getcwd(buffer, sizeof(buffer));

    /*
     * The stabs help the internal debugger as they are an indication that it
     * is sensible to step into a thunk/trampoline.
     */
    fprintf( outfile, ".stabs \"%s/\",100,0,0,Code_Start\n", buffer);
    fprintf( outfile, ".stabs \"%s\",100,0,0,Code_Start\n", specfile);
#endif

    fprintf( outfile, "\t.text\n" );
    fprintf( outfile, "\t.align 4\n" );
    fprintf( outfile, "Code_Start:\n" );

    /* Output code for all register functions */

    for (i = Base, odp = OrdinalDefinitions + Base; i <= Limit; i++, odp++)
    {
        if (odp->type != TYPE_REGISTER) continue;
        fprintf( outfile, "\n/* %s.%d (%s) */\n", DLLName, i, odp->name);
        fprintf( outfile, "\t.align 4\n" );
#ifdef USE_STABS
        fprintf( outfile, ".stabs \"%s_%d:F1\",36,0,%d,%s_%d\n", 
                 DLLName, i, odp->lineno, DLLName, i);
#endif
        fprintf( outfile, "%s_%d:\n", DLLName, i );
#ifdef USE_STABS
        fprintf( outfile, ".stabn 68,0,%d,0\n", odp->lineno);
#endif
        fprintf( outfile, "\tpushl $" PREFIX "%s\n",odp->u.func.link_name);
        fprintf( outfile, "\tjmp " PREFIX "CALL32_Regs\n" );
    }

    /* Output code for all stubs functions */

    nb_stubs = 0;
    for (i = Base, odp = OrdinalDefinitions + Base; i <= Limit; i++, odp++)
    {
        if (odp->type != TYPE_STUB) continue;
        fprintf( outfile, "\n/* %s.%d (%s) */\n", DLLName, i, odp->name);
#ifdef USE_STABS
        fprintf( outfile, ".stabs \"%s_%d:F1\",36,0,%d,%s_%d\n", 
                 DLLName, i, odp->lineno, DLLName, i);
#endif
        fprintf( outfile, "%s_%d:\n", DLLName, i );
#ifdef USE_STABS
        fprintf( outfile, ".stabn 68,0,%d,0\n", odp->lineno);
#endif
        fprintf( outfile, "\tpushl $Name_%d\n", i );
        fprintf( outfile, "\tpushl $%d\n", i );
        if (++nb_stubs == 1)
        {
            fprintf( outfile, "DoStub:\n" );
            fprintf( outfile, "\tpushl $DLLName\n" );
            fprintf( outfile, "\tcall " PREFIX "RELAY_Unimplemented32\n" );
        }
        else fprintf( outfile, "\tjmp DoStub\n" );
    }

    /* Output the DLL functions table */

    fprintf( outfile, "\t.text\n" );
    fprintf( outfile, "\t.align 4\n" );
    fprintf( outfile, "Functions:\n" );
    for (i = Base, odp = OrdinalDefinitions + Base; i <= Limit; i++, odp++)
    {
        switch(odp->type)
        {
        case TYPE_INVALID:
            fprintf( outfile, "\t.long 0\n" );
            break;
        case TYPE_VARARGS:
            fprintf( outfile, "\t.long " PREFIX "%s\n",odp->u.vargs.link_name);
            break;
        case TYPE_EXTERN:
            fprintf( outfile, "\t.long " PREFIX "%s\n", odp->u.ext.link_name );
            break;
        case TYPE_STDCALL:
        case TYPE_CDECL:
            fprintf( outfile, "\t.long " PREFIX "%s\n", odp->u.func.link_name);
            break;
        case TYPE_REGISTER:
        case TYPE_STUB:
            fprintf( outfile, "\t.long %s_%d\n", DLLName, i );
            break;
        default:
            fprintf(stderr,"build: function type %d not available for Win32\n",
                    odp->type);
            return -1;
        }
    }

    /* Output the DLL names table */

    fprintf( outfile, "FuncNames:\n" );
    for (i = Base, odp = OrdinalDefinitions + Base; i <= Limit; i++, odp++)
    {
        if (odp->type != TYPE_INVALID)
            fprintf( outfile, "\t.long Name_%d\n", i );
    }

    /* Output the DLL argument types */

    fprintf( outfile, "ArgTypes:\n" );
    for (i = Base, odp = OrdinalDefinitions + Base; i <= Limit; i++, odp++)
    {
    	unsigned int j, mask = 0;
	if ((odp->type == TYPE_STDCALL) || (odp->type == TYPE_CDECL))
	    for (j = 0; odp->u.func.arg_types[j]; j++)
            {
                if (odp->u.func.arg_types[j] == 't') mask |= 1<< (j*2);
                if (odp->u.func.arg_types[j] == 'W') mask |= 2<< (j*2);
	    }
	fprintf( outfile, "\t.long %ld\n",mask);
    }

    /* Output the DLL ordinals table */

    fprintf( outfile, "FuncOrdinals:\n" );
    nb_names = 0;
    for (i = Base, odp = OrdinalDefinitions + Base; i <= Limit; i++, odp++)
    {
        if (odp->type == TYPE_INVALID) continue;
        nb_names++;
        /* Some assemblers do not have .word */
        fprintf( outfile, "\t.byte %d,%d\n", LOBYTE(i), HIBYTE(i) );
    }

    /* Output the DLL names */

    for (i = Base, odp = OrdinalDefinitions + Base; i <= Limit; i++, odp++)
    {
        if (odp->type != TYPE_INVALID)
            fprintf( outfile, "Name_%d:\t.ascii \"%s\\0\"\n", i, odp->name );
    }

    /* Output the DLL functions arguments */

    args = p = (unsigned char *)xmalloc( Limit - Base + 1 );
    for (i = Base, odp = OrdinalDefinitions + Base; i <= Limit; i++, odp++)
    {
        switch(odp->type)
        {
        case TYPE_STDCALL:
            *p++ = (unsigned char)strlen(odp->u.func.arg_types);
            break;
        case TYPE_CDECL:
            *p++ = 0x80 | (unsigned char)strlen(odp->u.func.arg_types);
            break;
        case TYPE_REGISTER:
            *p++ = 0xfe;
            break;
        default:
            *p++ = 0xff;
            break;
        }
    }
    DumpBytes( outfile, args, Limit - Base + 1, NULL, "FuncArgs" );

    /* Output the DLL descriptor */

    fprintf( outfile, "DLLName:\t.ascii \"%s\\0\"\n", DLLName );
    fprintf( outfile, "\t.align 4\n" );
    fprintf( outfile, "\t.globl " PREFIX "%s_Descriptor\n", DLLName );
    fprintf( outfile, PREFIX "%s_Descriptor:\n", DLLName );
    fprintf( outfile, "\t.long DLLName\n" );          /* Name */
    fprintf( outfile, "\t.long %d\n", Base );         /* Base */
    fprintf( outfile, "\t.long %d\n", Limit+1-Base ); /* Number of functions */
    fprintf( outfile, "\t.long %d\n", nb_names );     /* Number of names */
    fprintf( outfile, "\t.long Functions\n" );        /* Functions */
    fprintf( outfile, "\t.long FuncNames\n" );        /* Function names */
    fprintf( outfile, "\t.long FuncOrdinals\n" );     /* Function ordinals */
    fprintf( outfile, "\t.long FuncArgs\n" );         /* Function arguments */
    fprintf( outfile, "\t.long ArgTypes\n" );         /* Function argtypes */
#ifdef USE_STABS
    fprintf( outfile, "\t.text\n");
    fprintf( outfile, "\t.stabs \"\",100,0,0,.Letext\n");
    fprintf( outfile, ".Letext:\n");
#endif
    return 0;
}


/*******************************************************************
 *         BuildSpec16File
 *
 * Build a Win16 assembly file from a spec file.
 */
static int BuildSpec16File( char * specfile, FILE *outfile )
{
    ORDDEF *odp;
    int i;
    int code_offset, data_offset, module_size;
    unsigned char *data;

    data = (unsigned char *)xmalloc( 0x10000 );
    memset( data, 0, 16 );
    data_offset = 16;

    fprintf( outfile, "/* File generated automatically; do not edit! */\n" );
    fprintf( outfile, "\t.text\n" );
    fprintf( outfile, "Code_Start:\n" );
    code_offset = 0;

    odp = OrdinalDefinitions;
    for (i = 0; i <= Limit; i++, odp++)
    {
        switch (odp->type)
        {
          case TYPE_INVALID:
            odp->offset = 0xffff;
            break;

          case TYPE_ABS:
            odp->offset = LOWORD(odp->u.abs.value);
            break;

          case TYPE_BYTE:
            odp->offset = data_offset;
            data_offset += StoreVariableCode( data + data_offset, 1, odp);
            break;

          case TYPE_WORD:
            odp->offset = data_offset;
            data_offset += StoreVariableCode( data + data_offset, 2, odp);
            break;

          case TYPE_LONG:
            odp->offset = data_offset;
            data_offset += StoreVariableCode( data + data_offset, 4, odp);
            break;

          case TYPE_RETURN:
            fprintf( outfile,"/* %s.%d */\n", DLLName, i);
            fprintf( outfile,"\tmovw $%d,%%ax\n",LOWORD(odp->u.ret.ret_value));
            fprintf( outfile,"\tmovw $%d,%%dx\n",HIWORD(odp->u.ret.ret_value));
            fprintf( outfile,"\t.byte 0x66\n");
            if (odp->u.ret.arg_size != 0)
                fprintf( outfile, "\tlret $%d\n\n", odp->u.ret.arg_size);
            else
            {
                fprintf( outfile, "\tlret\n");
                fprintf( outfile, "\tnop\n");
                fprintf( outfile, "\tnop\n\n");
            }
            odp->offset = code_offset;
            code_offset += 12;  /* Assembly code is 12 bytes long */
            break;

          case TYPE_REGISTER:
          case TYPE_PASCAL:
          case TYPE_PASCAL_16:
          case TYPE_STUB:
            fprintf( outfile, "/* %s.%d */\n", DLLName, i);
            fprintf( outfile, "\tpushw %%bp\n" );
            fprintf( outfile, "\tpushl $" PREFIX "%s\n",odp->u.func.link_name);
            /* FreeBSD does not understand lcall, so do it the hard way */
            fprintf( outfile, "\t.byte 0x9a\n" );
            fprintf( outfile, "\t.long " PREFIX "CallFrom16_%s_%s\n",
                     (odp->type == TYPE_REGISTER) ? "regs" :
                     (odp->type == TYPE_PASCAL) ? "long" : "word",
                     odp->u.func.arg_types );
            fprintf( outfile,"\t.byte 0x%02x,0x%02x\n", /* Some asms don't have .word */
                     LOBYTE(WINE_CODE_SELECTOR), HIBYTE(WINE_CODE_SELECTOR) );
            fprintf( outfile, "\tnop\n" );
            fprintf( outfile, "\tnop\n\n" );
            odp->offset = code_offset;
            code_offset += 16;  /* Assembly code is 16 bytes long */
            break;
		
          default:
            fprintf(stderr,"build: function type %d not available for Win16\n",
                    odp->type);
            return -1;
	}
    }

    if (!code_offset)  /* Make sure the code segment is not empty */
    {
        fprintf( outfile, "\t.byte 0\n" );
        code_offset++;
    }

    /* Output data segment */

    DumpBytes( outfile, data, data_offset, NULL, "Data_Start" );

    /* Build the module */

    module_size = BuildModule16( outfile, code_offset, data_offset );

    /* Output the DLL descriptor */

    fprintf( outfile, "\t.text\n" );
    fprintf( outfile, "DLLName:\t.ascii \"%s\\0\"\n", DLLName );
    fprintf( outfile, "\t.align 4\n" );
    fprintf( outfile, "\t.globl " PREFIX "%s_Descriptor\n", DLLName );
    fprintf( outfile, PREFIX "%s_Descriptor:\n", DLLName );
    fprintf( outfile, "\t.long DLLName\n" );          /* Name */
    fprintf( outfile, "\t.long Module_Start\n" );     /* Module start */
    fprintf( outfile, "\t.long %d\n", module_size );  /* Module size */
    fprintf( outfile, "\t.long Code_Start\n" );       /* Code start */
    fprintf( outfile, "\t.long Data_Start\n" );       /* Data start */
    return 0;
}


/*******************************************************************
 *         BuildSpecFile
 *
 * Build an assembly file from a spec file.
 */
static int BuildSpecFile( FILE *outfile, char *specname )
{
    SpecName = specname;
    SpecFp = fopen( specname, "r");
    if (SpecFp == NULL)
    {
	fprintf(stderr, "Could not open specification file, '%s'\n", specname);
        return -1;
    }

    if (ParseTopLevel() < 0) return -1;

    switch(SpecType)
    {
    case SPEC_WIN16:
        return BuildSpec16File( specname, outfile );
    case SPEC_WIN32:
        return BuildSpec32File( specname, outfile );
    default:
        fprintf( stderr, "%s: Missing 'type' declaration\n", specname );
        return -1;
    }
}


/*******************************************************************
 *         TransferArgs16To32
 *
 * Get the arguments from the 16-bit stack and push them on the 32-bit stack.
 * The 16-bit stack layout is:
 *   ...     ...
 *  (bp+8)    arg2
 *  (bp+6)    arg1
 *  (bp+4)    cs
 *  (bp+2)    ip
 *  (bp)      bp
 */
static int TransferArgs16To32( FILE *outfile, char *args )
{
    int i, pos16, pos32;

    /* Save ebx first */

    fprintf( outfile, "\tpushl %%ebx\n" );

    /* Get the 32-bit stack pointer */

    fprintf( outfile, "\tmovl " PREFIX "CALLTO16_Saved32_esp,%%ebx\n" );

    /* Copy the arguments */

    pos16 = 6;  /* skip bp and return address */
    pos32 = 0;

    for (i = strlen(args); i > 0; i--)
    {
        pos32 -= 4;
        switch(args[i-1])
        {
        case 'w':  /* word */
            fprintf( outfile, "\tmovzwl %d(%%ebp),%%eax\n", pos16 );
            fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n", pos32 );
            pos16 += 2;
            break;

        case 's':  /* s_word */
            fprintf( outfile, "\tmovswl %d(%%ebp),%%eax\n", pos16 );
            fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n", pos32 );
            pos16 += 2;
            break;

        case 'l':  /* long or segmented pointer */
        case 'T':  /* segmented pointer to null-terminated string */
            fprintf( outfile, "\tmovl %d(%%ebp),%%eax\n", pos16 );
            fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n", pos32 );
            pos16 += 4;
            break;

        case 'p':  /* linear pointer */
        case 't':  /* linear pointer to null-terminated string */
            /* Get the selector */
            fprintf( outfile, "\tmovw %d(%%ebp),%%ax\n", pos16 + 2 );
            /* Get the selector base */
            fprintf( outfile, "\tandl $0xfff8,%%eax\n" );
            fprintf( outfile, "\tmovl " PREFIX "ldt_copy(%%eax),%%eax\n" );
            fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n", pos32 );
            /* Add the offset */
            fprintf( outfile, "\tmovzwl %d(%%ebp),%%eax\n", pos16 );
            fprintf( outfile, "\taddl %%eax,%d(%%ebx)\n", pos32 );
            pos16 += 4;
            break;

        default:
            fprintf( stderr, "Unknown arg type '%c'\n", args[i-1] );
        }
    }

    /* Restore ebx */
    
    fprintf( outfile, "\tpopl %%ebx\n" );

    return pos16 - 6;  /* Return the size of the 16-bit args */
}


/*******************************************************************
 *         BuildContext16
 *
 * Build the context structure on the 32-bit stack.
 */
static void BuildContext16( FILE *outfile )
{
    /* Save ebx first */

    fprintf( outfile, "\tpushl %%ebx\n" );

    /* Get the 32-bit stack pointer */

    fprintf( outfile, "\tmovl " PREFIX "CALLTO16_Saved32_esp,%%ebx\n" );

    /* Store the registers */

    fprintf( outfile, "\tpopl %d(%%ebx)\n", /* Get ebx from stack*/
             CONTEXTOFFSET(Ebx) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n",
             CONTEXTOFFSET(Eax) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %%ecx,%d(%%ebx)\n",
             CONTEXTOFFSET(Ecx) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %%edx,%d(%%ebx)\n",
             CONTEXTOFFSET(Edx) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %%esi,%d(%%ebx)\n",
             CONTEXTOFFSET(Esi) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %%edi,%d(%%ebx)\n",
             CONTEXTOFFSET(Edi) - sizeof(CONTEXT) );

    fprintf( outfile, "\tmovzwl -10(%%ebp),%%eax\n" ); /* Get %ds from stack*/
    fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n",
             CONTEXTOFFSET(SegDs) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovzwl -6(%%ebp),%%eax\n" ); /* Get %es from stack*/
    fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n",
             CONTEXTOFFSET(SegEs) - sizeof(CONTEXT) );
    fprintf( outfile, "\tpushfl\n" );
    fprintf( outfile, "\tpopl %d(%%ebx)\n",
             CONTEXTOFFSET(EFlags) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl -16(%%ebp),%%eax\n" ); /* Get %ebp from stack */
    fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n",
             CONTEXTOFFSET(Ebp) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovzwl 2(%%ebp),%%eax\n" ); /* Get %ip from stack */
    fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n",
             CONTEXTOFFSET(Eip) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovzwl 4(%%ebp),%%eax\n" ); /* Get %cs from stack */
    fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n",
             CONTEXTOFFSET(SegCs) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovw %%fs,%%ax\n" );
    fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n",
             CONTEXTOFFSET(SegFs) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovw %%gs,%%ax\n" );
    fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n",
             CONTEXTOFFSET(SegGs) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovw %%ss,%%ax\n" );
    fprintf( outfile, "\tmovl %%eax,%d(%%ebx)\n",
             CONTEXTOFFSET(SegSs) - sizeof(CONTEXT) );
#if 0
    fprintf( outfile, "\tfsave %d(%%ebx)\n",
             CONTEXTOFFSET(FloatSave) - sizeof(CONTEXT) );
#endif
}


/*******************************************************************
 *         RestoreContext16
 *
 * Restore the registers from the context structure.
 * %edx must point to the 32-bit stack top.
 */
static void RestoreContext16( FILE *outfile )
{
    /* Get the 32-bit stack pointer */

    fprintf( outfile, "\tmovl %%edx,%%ebx\n" );

    /* Remove everything up to the return address from the 16-bit stack */

    fprintf( outfile, "\taddl $22,%%esp\n" );

    /* Restore the registers */

    fprintf( outfile, "\tmovl %d(%%ebx),%%ecx\n",
             CONTEXTOFFSET(Ecx) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %d(%%ebx),%%edx\n",
             CONTEXTOFFSET(Edx) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %d(%%ebx),%%esi\n",
             CONTEXTOFFSET(Esi) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %d(%%ebx),%%edi\n",
             CONTEXTOFFSET(Edi) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %d(%%ebx),%%ebp\n",
             CONTEXTOFFSET(Ebp) - sizeof(CONTEXT) );
    fprintf( outfile, "\tpushw %d(%%ebx)\n",  /* Push new cs */
             CONTEXTOFFSET(SegCs) - sizeof(CONTEXT) );
    fprintf( outfile, "\tpushw %d(%%ebx)\n",  /* Push new ip */
             CONTEXTOFFSET(Eip) - sizeof(CONTEXT) );
    fprintf( outfile, "\tpushw %d(%%ebx)\n",  /* Push new ds */
             CONTEXTOFFSET(SegDs) - sizeof(CONTEXT) );
    fprintf( outfile, "\tpushw %d(%%ebx)\n",  /* Push new es */
             CONTEXTOFFSET(SegEs) - sizeof(CONTEXT) );
    fprintf( outfile, "\tpushl %d(%%ebx)\n",
             CONTEXTOFFSET(EFlags) - sizeof(CONTEXT) );
    fprintf( outfile, "\tpopfl\n" );
    fprintf( outfile, "\tmovl %d(%%ebx),%%eax\n",
             CONTEXTOFFSET(Eax) - sizeof(CONTEXT) );
    fprintf( outfile, "\tmovl %d(%%ebx),%%ebx\n",
             CONTEXTOFFSET(Ebx) - sizeof(CONTEXT) );
    fprintf( outfile, "\tpopw %%es\n" );  /* Set es */
    fprintf( outfile, "\tpopw %%ds\n" );  /* Set ds */
}


/*******************************************************************
 *         BuildCallFrom16Func
 *
 * Build a 16-bit-to-Wine callback function. The syntax of the function
 * profile is: type_xxxxx, where 'type' is one of 'regs', 'word' or
 * 'long' and each 'x' is an argument ('w'=word, 's'=signed word,
 * 'l'=long, 'p'=linear pointer, 't'=linear pointer to null-terminated string,
 * 'T'=segmented pointer to null-terminated string).
 * For register functions, the arguments are ignored, but they are still
 * removed from the stack upon return.
 *
 * Stack layout upon entry to the callback function:
 *  ...           ...
 * (sp+18) word   first 16-bit arg
 * (sp+16) word   cs
 * (sp+14) word   ip
 * (sp+12) word   bp
 * (sp+8)  long   32-bit entry point (used to store edx)
 * (sp+6)  word   high word of cs (always 0, used to store es)
 * (sp+4)  word   low word of cs of 16-bit entry point
 * (sp+2)  word   high word of ip (always 0, used to store ds)
 * (sp)    word   low word of ip of 16-bit entry point
 *
 * Added on the stack:
 * (sp-4)  long   ebp
 * (sp-6)  word   saved previous sp
 * (sp-8)  word   saved previous ss
 */
static void BuildCallFrom16Func( FILE *outfile, char *profile )
{
    int argsize = 0;
    int short_ret = 0;
    int reg_func = 0;
    char *args = profile + 5;

    /* Parse function type */

    if (!strncmp( "word_", profile, 5 )) short_ret = 1;
    else if (!strncmp( "regs_", profile, 5 )) reg_func = 1;
    else if (strncmp( "long_", profile, 5 ))
    {
        fprintf( stderr, "Invalid function name '%s', ignored\n", profile );
        return;
    }

    /* Function header */

    fprintf( outfile, "\n\t.align 4\n" );
#ifdef USE_STABS
    fprintf( outfile, ".stabs \"CallFrom16_%s:F1\",36,0,0," PREFIX "CallFrom16_%s\n", 
	     profile, profile);
#endif
    fprintf( outfile, "\t.globl " PREFIX "CallFrom16_%s\n", profile );
    fprintf( outfile, PREFIX "CallFrom16_%s:\n", profile );

    /* Setup bp to point to its copy on the stack */

    fprintf( outfile, "\tpushl %%ebp\n" );  /* Save the full 32-bit ebp */
    fprintf( outfile, "\tmovzwl %%sp,%%ebp\n" );
    fprintf( outfile, "\taddw $16,%%bp\n" );

    /* Save 16-bit ds and es */

    /* Stupid FreeBSD assembler doesn't know these either */
    /* fprintf( outfile, "\tmovw %%ds,-10(%%ebp)\n" ); */
    fprintf( outfile, "\t.byte 0x66,0x8c,0x5d,0xf6\n" );
    /* fprintf( outfile, "\tmovw %%es,-6(%%ebp)\n" ); */
    fprintf( outfile, "\t.byte 0x66,0x8c,0x45,0xfa\n" );

    /* Restore 32-bit ds and es */

    fprintf( outfile, "\tpushl $0x%04x%04x\n",
             WINE_DATA_SELECTOR, WINE_DATA_SELECTOR );
    fprintf( outfile, "\tpopw %%ds\n" );
    fprintf( outfile, "\tpopw %%es\n" );


    /* Save the 16-bit stack */

    fprintf( outfile, "\tpushl " PREFIX "IF1632_Saved16_ss_sp\n" );
#ifdef __svr4__
    fprintf( outfile,"\tdata16\n");
#endif
    fprintf( outfile, "\tmovw %%ss," PREFIX "IF1632_Saved16_ss_sp+2\n" );
    fprintf( outfile, "\tmovw %%sp," PREFIX "IF1632_Saved16_ss_sp\n" );

    /* Transfer the arguments */

    if (reg_func) BuildContext16( outfile );
    else if (*args) argsize = TransferArgs16To32( outfile, args );

    /* Get the address of the API function */

    fprintf( outfile, "\tmovl -4(%%ebp),%%eax\n" );

    /* If necessary, save %edx over the API function address */

    if (!reg_func && short_ret)
        fprintf( outfile, "\tmovl %%edx,-4(%%ebp)\n" );

    /* Switch to the 32-bit stack */

    fprintf( outfile, "\tmovl " PREFIX "CALLTO16_Saved32_esp,%%ebp\n" );
    fprintf( outfile, "\tpushw %%ds\n" );
    fprintf( outfile, "\tpopw %%ss\n" );
    fprintf( outfile, "\tleal -%d(%%ebp),%%esp\n",
             reg_func ? sizeof(CONTEXT) : 4 * strlen(args) );
    if (reg_func)  /* Push the address of the context struct */
        fprintf( outfile, "\tpushl %%esp\n" );

    /* Setup %ebp to point to the previous stack frame (built by CallTo16) */

    fprintf( outfile, "\taddl $%d,%%ebp\n", STRUCTOFFSET(STACK32FRAME,ebp) );

    /* Print the debug information before the call */

    if (debugging)
    {
        fprintf( outfile, "\tpushl %%eax\n" );
        fprintf( outfile, "\tpushl $Profile_%s\n", profile );
        fprintf( outfile, "\tpushl $%d\n", reg_func ? 2 : (short_ret ? 1 : 0));
        fprintf( outfile, "\tcall " PREFIX "RELAY_DebugCallFrom16\n" );
        fprintf( outfile, "\tpopl %%eax\n" );
        fprintf( outfile, "\tpopl %%eax\n" );
        fprintf( outfile, "\tpopl %%eax\n" );
    }

    /* Call the entry point */

    fprintf( outfile, "\tcall %%eax\n" );

    /* Print the debug information after the call */

    if (debugging)
    {
        if (reg_func)
        {
            /* Push again the address of the context struct in case */
            /* it has been removed by an stdcall function */
            fprintf( outfile, "\tleal -%d(%%ebp),%%esp\n",
                     sizeof(CONTEXT) + STRUCTOFFSET(STACK32FRAME,ebp) );
            fprintf( outfile, "\tpushl %%esp\n" );
        }
        fprintf( outfile, "\tpushl %%eax\n" );
        fprintf( outfile, "\tpushl $%d\n", reg_func ? 2 : (short_ret ? 1 : 0));
        fprintf( outfile, "\tcall " PREFIX "RELAY_DebugCallFrom16Ret\n" );
        fprintf( outfile, "\tpopl %%eax\n" );
        fprintf( outfile, "\tpopl %%eax\n" );
    }

    /* Restore the value of the saved 32-bit stack pointer */

    fprintf( outfile, "\tleal -%d(%%ebp),%%edx\n",
             STRUCTOFFSET(STACK32FRAME,ebp) );
    fprintf( outfile, "movl %%edx," PREFIX "CALLTO16_Saved32_esp\n" );

    /* Restore the 16-bit stack */

#ifdef __svr4__
    fprintf( outfile, "\tdata16\n");
#endif
    fprintf( outfile, "\tmovw " PREFIX "IF1632_Saved16_ss_sp+2,%%ss\n" );
    fprintf( outfile, "\tmovw " PREFIX "IF1632_Saved16_ss_sp,%%sp\n" );
    fprintf( outfile, "\tpopl " PREFIX "IF1632_Saved16_ss_sp\n" );

    if (reg_func)
    {
        /* Calc the arguments size */
        while (*args)
        {
            switch(*args)
            {
            case 'w':
            case 's':
                argsize += 2;
                break;
            case 'p':
            case 't':
            case 'l':
	    case 'T':
                argsize += 4;
                break;
            default:
                fprintf( stderr, "Unknown arg type '%c'\n", *args );
            }
            args++;
        }

        /* Restore registers from the context structure */
        RestoreContext16( outfile );
    }
    else
    {
        /* Restore high 16 bits of ebp */
        fprintf( outfile, "\tpopl %%ebp\n" );

        /* Restore ds and es */
        fprintf( outfile, "\tincl %%esp\n" );      /* Remove ip */
        fprintf( outfile, "\tincl %%esp\n" );
        fprintf( outfile, "\tpopl %%edx\n" );      /* Remove cs and ds */
        fprintf( outfile, "\tmovw %%dx,%%ds\n" );  /* and restore ds */
        fprintf( outfile, "\tpopw %%es\n" );       /* Restore es */

        if (short_ret) fprintf( outfile, "\tpopl %%edx\n" );  /* Restore edx */
        else
        {
            /* Get the return value into dx:ax */
            fprintf( outfile, "\tmovl %%eax,%%edx\n" );
            fprintf( outfile, "\tshrl $16,%%edx\n" );
            /* Remove API entry point */
            fprintf( outfile, "\taddl $4,%%esp\n" );
        }

        /* Restore low 16 bits of ebp */
        fprintf( outfile, "\tpopw %%bp\n" );
    }

    /* Remove the arguments and return */

    if (argsize)
    {
        fprintf( outfile, "\t.byte 0x66\n" );
        fprintf( outfile, "\tlret $%d\n", argsize );
    }
    else
    {
        fprintf( outfile, "\t.byte 0x66\n" );
        fprintf( outfile, "\tlret\n" );
    }
}


/*******************************************************************
 *         BuildCallTo16Func
 *
 * Build a Wine-to-16-bit callback function.
 *
 * Stack frame of the callback function:
 *  ...      ...
 * (ebp+16) arg2
 * (ebp+12) arg1
 * (ebp+8)  func to call
 * (ebp+4)  return address
 * (ebp)    previous ebp
 *
 * Prototypes for the CallTo16 functions:
 *   extern WINAPI WORD CallTo16_word_xxx( FARPROC16 func, args... );
 *   extern WINAPI LONG CallTo16_long_xxx( FARPROC16 func, args... );
 *   extern WINAPI void CallTo16_regs_{short,long}( const CONTEXT *context );
 */
static void BuildCallTo16Func( FILE *outfile, char *profile )
{
    int short_ret = 0;
    int reg_func = 0;
    char *args = profile + 5;

    if (!strncmp( "word_", profile, 5 )) short_ret = 1;
    else if (!strncmp( "regs_", profile, 5 )) reg_func = 1;
    else if (strncmp( "long_", profile, 5 ))
    {
        fprintf( stderr, "Invalid function name '%s'.\n", profile );
        exit(1);
    }

    /* Function header */

    fprintf( outfile, "\n\t.align 4\n" );
#ifdef USE_STABS
    fprintf( outfile, ".stabs \"CallTo16_%s:F1\",36,0,0," PREFIX "CallTo16_%s\n", 
	     profile, profile);
#endif
    fprintf( outfile, "\t.globl " PREFIX "CallTo16_%s\n", profile );
    fprintf( outfile, PREFIX "CallTo16_%s:\n", profile );

    /* Entry code */

    fprintf( outfile, "\tpushl %%ebp\n" );
    fprintf( outfile, "\tmovl %%esp,%%ebp\n" );

    /* Call the actual CallTo16 routine (simulate a lcall) */

    fprintf( outfile, "\tpushw $0\n" );
    fprintf( outfile, "\tpushw %%cs\n" );
    fprintf( outfile, "\tcall do_callto16_%s\n", profile );

    /* Exit code */

    /* FIXME: this is a hack because of task.c */
    if (!strcmp( profile, "word_" ))
    {
        fprintf( outfile, ".globl " PREFIX "CALLTO16_Restore\n" );
        fprintf( outfile, PREFIX "CALLTO16_Restore:\n" );
    }
    fprintf( outfile, "\tpopl %%ebp\n" );
    fprintf( outfile, "\tret $%d\n", strlen(args) + 1 );

    /* Start of the actual CallTo16 routine */

    /* Save the 32-bit registers */

    fprintf( outfile, "do_callto16_%s:\n", profile );
    fprintf( outfile, "\tpushl %%ebx\n" );
    fprintf( outfile, "\tpushl %%ecx\n" );
    fprintf( outfile, "\tpushl %%edx\n" );
    fprintf( outfile, "\tpushl %%esi\n" );
    fprintf( outfile, "\tpushl %%edi\n" );

    /* Save the 32-bit stack */

    fprintf( outfile, "\tmovl %%esp," PREFIX "CALLTO16_Saved32_esp\n" );
    fprintf( outfile, "\tmovl %%ebp,%%ebx\n" );

    /* Print debugging info */

    if (debugging)
    {
        /* Push the address of the first argument */
        fprintf( outfile, "\tleal 8(%%ebp),%%eax\n" );
        fprintf( outfile, "\tpushl $%d\n", reg_func ? -1 : strlen(args) );
        fprintf( outfile, "\tpushl %%eax\n" );
        fprintf( outfile, "\tcall " PREFIX "RELAY_DebugCallTo16\n" );
        fprintf( outfile, "\tpopl %%eax\n" );
        fprintf( outfile, "\tpopl %%eax\n" );
    }

    if (reg_func)
    {
        /* Switch to the 16-bit stack, saving the current %%esp, */
        /* and adding the specified offset to the new sp */
        fprintf( outfile, "\tmovzwl " PREFIX "IF1632_Saved16_ss_sp,%%edx\n" );
        fprintf( outfile, "\tleal -4(%%edx),%%edx\n" );
        fprintf( outfile, "\tmovl 12(%%ebx),%%eax\n" ); /* Get the offset */
        fprintf( outfile, "\taddl %%edx,%%eax\n" );
#ifdef __svr4__
        fprintf( outfile,"\tdata16\n");
#endif
        fprintf( outfile, "\tmovw " PREFIX "IF1632_Saved16_ss_sp+2,%%ss\n" );
        fprintf( outfile, "\txchgl %%esp,%%eax\n" );
        fprintf( outfile, "\t.byte 0x36\n" /* %ss: */ );
        fprintf( outfile, "\tmovl %%eax,0(%%edx)\n" );

        /* Get the registers. ebx is handled later on. */

        fprintf( outfile, "\tmovl 8(%%ebx),%%ebx\n" );
        fprintf( outfile, "\tmovl %d(%%ebx),%%eax\n", CONTEXTOFFSET(SegEs) );
        fprintf( outfile, "\tmovw %%ax,%%es\n" );
        fprintf( outfile, "\tmovl %d(%%ebx),%%ebp\n", CONTEXTOFFSET(Ebp) );
        fprintf( outfile, "\tmovl %d(%%ebx),%%eax\n", CONTEXTOFFSET(Eax) );
        fprintf( outfile, "\tmovl %d(%%ebx),%%ecx\n", CONTEXTOFFSET(Ecx) );
        fprintf( outfile, "\tmovl %d(%%ebx),%%edx\n", CONTEXTOFFSET(Edx) );
        fprintf( outfile, "\tmovl %d(%%ebx),%%esi\n", CONTEXTOFFSET(Esi) );
        fprintf( outfile, "\tmovl %d(%%ebx),%%edi\n", CONTEXTOFFSET(Edi) );

        /* Push the return address 
	 * With _short suffix, we push 16:16 address (normal lret)
	 * With _long suffix, we push 16:32 address (0x66 lret, for KERNEL32_45)
	 */
	if (!strncmp(profile,"regs_short",10))
	    fprintf( outfile, "\tpushl " PREFIX "CALLTO16_RetAddr_regs\n" );
	else 
	{
	    fprintf( outfile, "\tpushw $0\n" );
	    fprintf( outfile, "\tpushw " PREFIX "CALLTO16_RetAddr_regs+2\n" );
	    fprintf( outfile, "\tpushw $0\n" );
	    fprintf( outfile, "\tpushw " PREFIX "CALLTO16_RetAddr_regs\n" );
	}

        /* Push the called routine address */

        fprintf( outfile, "\tpushw %d(%%ebx)\n", CONTEXTOFFSET(SegCs) );
        fprintf( outfile, "\tpushw %d(%%ebx)\n", CONTEXTOFFSET(Eip) );

        /* Get the 16-bit ds */

        fprintf( outfile, "\tpushw %d(%%ebx)\n", CONTEXTOFFSET(SegDs) );
        /* Get ebx from the 32-bit stack */
        fprintf( outfile, "\tmovl %d(%%ebx),%%ebx\n", CONTEXTOFFSET(Ebx) );
        fprintf( outfile, "\tpopw %%ds\n" );
    }
    else  /* not a register function */
    {
        int pos = 12;  /* first argument position */

        /* Switch to the 16-bit stack, saving the current %%esp */
        fprintf( outfile, "\tmovl %%esp,%%eax\n" );
#ifdef __svr4__
        fprintf( outfile,"\tdata16\n");
#endif
        fprintf( outfile, "\tmovw " PREFIX "IF1632_Saved16_ss_sp+2,%%ss\n" );
        fprintf( outfile, "\tmovw " PREFIX "IF1632_Saved16_ss_sp,%%sp\n" );
        fprintf( outfile, "\tpushl %%eax\n" );

        /* Make %bp point to the previous stackframe (built by CallFrom16) */
        fprintf( outfile, "\tmovzwl %%sp,%%ebp\n" );
        fprintf( outfile, "\tleal %d(%%ebp),%%ebp\n",
                 STRUCTOFFSET(STACK16FRAME,bp) + 4 /* for saved %%esp */ );

        /* Transfer the arguments */

        while (*args)
        {
            switch(*args++)
            {
            case 'w': /* word */
                fprintf( outfile, "\tpushw %d(%%ebx)\n", pos );
                break;
            case 'l': /* long */
                fprintf( outfile, "\tpushl %d(%%ebx)\n", pos );
                break;
	    default:
		fprintf( stderr, "Unexpected case '%c' in BuildCallTo16Func\n",
			args[-1] );
            }
            pos += 4;
        }

        /* Push the return address */

        fprintf( outfile, "\tpushl " PREFIX "CALLTO16_RetAddr_%s\n",
                 short_ret ? "word" : "long" );

        /* Push the called routine address */

        fprintf( outfile, "\tpushl 8(%%ebx)\n" );

        /* Set %ds and %es (and %ax just in case) equal to %ss */

        fprintf( outfile, "\tmovw %%ss,%%ax\n" );
        fprintf( outfile, "\tmovw %%ax,%%ds\n" );
        fprintf( outfile, "\tmovw %%ax,%%es\n" );
    }

    /* Jump to the called routine */

    fprintf( outfile, "\t.byte 0x66\n" );
    fprintf( outfile, "\tlret\n" );
}


/*******************************************************************
 *         BuildRet16Func
 *
 * Build the return code for 16-bit callbacks
 */
static void BuildRet16Func( FILE *outfile )
{
    fprintf( outfile, "\t.globl " PREFIX "CALLTO16_Ret_word\n" );
    fprintf( outfile, "\t.globl " PREFIX "CALLTO16_Ret_long\n" );
    fprintf( outfile, "\t.globl " PREFIX "CALLTO16_Ret_regs\n" );

    fprintf( outfile, PREFIX "CALLTO16_Ret_word:\n" );
    fprintf( outfile, "\txorl %%edx,%%edx\n" );

    /* Remove the arguments just in case */

    fprintf( outfile, PREFIX "CALLTO16_Ret_long:\n" );
    fprintf( outfile, "\tleal -%d(%%ebp),%%esp\n",
                 STRUCTOFFSET(STACK16FRAME,bp) + 4 /* for saved %%esp */ );

    /* Put return value into %eax */

    fprintf( outfile, PREFIX "CALLTO16_Ret_regs:\n" );
    fprintf( outfile, "\tshll $16,%%edx\n" );
    fprintf( outfile, "\tmovw %%ax,%%dx\n" );
    fprintf( outfile, "\tmovl %%edx,%%eax\n" );

    /* Restore 32-bit segment registers and stack*/

    fprintf( outfile, "\tpopl %%ecx\n" );  /* Get the saved %%esp */
    fprintf( outfile, "\tmovw $0x%04x,%%bx\n", WINE_DATA_SELECTOR );
#ifdef __svr4__
    fprintf( outfile, "\tdata16\n");
#endif
    fprintf( outfile, "\tmovw %%bx,%%ds\n" );
#ifdef __svr4__
    fprintf( outfile, "\tdata16\n");
#endif
    fprintf( outfile, "\tmovw %%bx,%%es\n" );

    /* Restore the 32-bit stack */

#ifdef __svr4__
    fprintf( outfile, "\tdata16\n");
#endif
    fprintf( outfile, "\tmovw %%bx,%%ss\n" );
    fprintf( outfile, "\tmovl %%ecx,%%esp\n" );

    /* Restore the 32-bit registers */

    fprintf( outfile, "\tpopl %%edi\n" );
    fprintf( outfile, "\tpopl %%esi\n" );
    fprintf( outfile, "\tpopl %%edx\n" );
    fprintf( outfile, "\tpopl %%ecx\n" );
    fprintf( outfile, "\tpopl %%ebx\n" );

    /* Return to caller */

    fprintf( outfile, "\tlret\n" );

    /* Declare the return address variables */

    fprintf( outfile, "\t.data\n" );
    fprintf( outfile, "\t.globl " PREFIX "CALLTO16_RetAddr_word\n" );
    fprintf( outfile, "\t.globl " PREFIX "CALLTO16_RetAddr_long\n" );
    fprintf( outfile, "\t.globl " PREFIX "CALLTO16_RetAddr_regs\n" );
    fprintf( outfile, "\t.globl " PREFIX "CALLTO16_Saved32_esp\n" );
    fprintf( outfile, PREFIX "CALLTO16_RetAddr_word:\t.long 0\n" );
    fprintf( outfile, PREFIX "CALLTO16_RetAddr_long:\t.long 0\n" );
    fprintf( outfile, PREFIX "CALLTO16_RetAddr_regs:\t.long 0\n" );
    fprintf( outfile, PREFIX "CALLTO16_Saved32_esp:\t.long 0\n" );
    fprintf( outfile, "\t.text\n" );
}


/*******************************************************************
 *         BuildCallTo32LargeStack
 *
 * Build the function used to switch to the original 32-bit stack
 * before calling a 32-bit function from 32-bit code. This is used for
 * functions that need a large stack, like X bitmaps functions.
 *
 * The generated function has the following prototype:
 *   int xxx( int (*func)(), void *arg );
 *
 * The pointer to the function can be retrieved by calling CALL32_Init,
 * which also takes care of saving the current 32-bit stack pointer.
 *
 * Stack layout:
 *   ...     ...
 * (ebp+12)  arg
 * (ebp+8)   func
 * (ebp+4)   ret addr
 * (ebp)     ebp
 */
static void BuildCallTo32LargeStack( FILE *outfile )
{
    /* Initialization function */

    fprintf( outfile, "\n\t.align 4\n" );
#ifdef USE_STABS
    fprintf( outfile, ".stabs \"CALL32_Init:F1\",36,0,0," PREFIX "CALL32_Init\n");
#endif
    fprintf( outfile, "\t.globl " PREFIX "CALL32_Init\n" );
    fprintf( outfile, PREFIX "CALL32_Init:\n" );
    fprintf( outfile, "\tleal -256(%%esp),%%eax\n" );
    fprintf( outfile, "\tmovl %%eax,CALL32_Original32_esp\n" );
    fprintf( outfile, "\tmovl $CALL32_LargeStack,%%eax\n" );
    fprintf( outfile, "\tret\n" );

    /* Function header */

    fprintf( outfile, "\n\t.align 4\n" );
#ifdef USE_STABS
    fprintf( outfile, ".stabs \"CALL32_LargeStack:F1\",36,0,0,CALL32_LargeStack\n");
#endif
    fprintf( outfile, "CALL32_LargeStack:\n" );
    
    /* Entry code */

    fprintf( outfile, "\tpushl %%ebp\n" );
    fprintf( outfile, "\tmovl %%esp,%%ebp\n" );

    /* Switch to the original 32-bit stack pointer */

    fprintf( outfile, "\tmovl CALL32_Original32_esp, %%esp\n" );

    /* Transfer the argument and call the function */

    fprintf( outfile, "\tpushl 12(%%ebp)\n" );
    fprintf( outfile, "\tcall 8(%%ebp)\n" );

    /* Restore registers and return */

    fprintf( outfile, "\tmovl %%ebp,%%esp\n" );
    fprintf( outfile, "\tpopl %%ebp\n" );
    fprintf( outfile, "\tret\n" );

    /* Data */

    fprintf( outfile, "\t.data\n" );
    fprintf( outfile, "CALL32_Original32_esp:\t.long 0\n" );
    fprintf( outfile, "\t.text\n" );
}


/*******************************************************************
 *         BuildCallFrom32Regs
 *
 * Build a 32-bit-to-Wine call-back function for a 'register' function.
 * 'args' is the number of dword arguments.
 *
 * Stack layout:
 *   ...     ...
 * (esp+208) ret addr (or relay addr when debugging_relay is on)
 * (esp+204) entry point
 * (esp+0)   CONTEXT struct
 */
static void BuildCallFrom32Regs( FILE *outfile )
{
    /* Function header */

    fprintf( outfile, "\n\t.align 4\n" );
#ifdef USE_STABS
    fprintf( outfile, ".stabs \"CALL32_Regs:F1\",36,0,0," PREFIX "CALL32_Regs\n" );
#endif
    fprintf( outfile, "\t.globl " PREFIX "CALL32_Regs\n" );
    fprintf( outfile, PREFIX "CALL32_Regs:\n" );

    /* Build the context structure */

    fprintf( outfile, "\tpushw $0\n" );
    fprintf( outfile, "\tpushw %%ss\n" );
    fprintf( outfile, "\tpushl %%eax\n" );  /* %esp place holder */
    fprintf( outfile, "\tpushfl\n" );
    fprintf( outfile, "\tpushw $0\n" );
    fprintf( outfile, "\tpushw %%cs\n" );
    fprintf( outfile, "\tpushl 20(%%esp)\n" );  /* %eip at time of call */
    fprintf( outfile, "\tpushl %%ebp\n" );

    fprintf( outfile, "\tpushl %%eax\n" );
    fprintf( outfile, "\tpushl %%ecx\n" );
    fprintf( outfile, "\tpushl %%edx\n" );
    fprintf( outfile, "\tpushl %%ebx\n" );
    fprintf( outfile, "\tpushl %%esi\n" );
    fprintf( outfile, "\tpushl %%edi\n" );

    fprintf( outfile, "\txorl %%eax,%%eax\n" );
    fprintf( outfile, "\tmovw %%ds,%%ax\n" );
    fprintf( outfile, "\tpushl %%eax\n" );
    fprintf( outfile, "\tmovw %%es,%%ax\n" );
    fprintf( outfile, "\tpushl %%eax\n" );
    fprintf( outfile, "\tmovw %%fs,%%ax\n" );
    fprintf( outfile, "\tpushl %%eax\n" );
    fprintf( outfile, "\tmovw %%gs,%%ax\n" );
    fprintf( outfile, "\tpushl %%eax\n" );

    fprintf( outfile, "\tleal -%d(%%esp),%%esp\n",
             sizeof(FLOATING_SAVE_AREA) + 6 * sizeof(DWORD) /* DR regs */ );
    fprintf( outfile, "\tpushl $0x0001001f\n" );  /* ContextFlags */

    fprintf( outfile, "\tfsave %d(%%esp)\n", CONTEXTOFFSET(FloatSave) );

    fprintf( outfile, "\tleal %d(%%esp),%%eax\n",
             sizeof(CONTEXT) + 4 ); /* %esp at time of call */
    fprintf( outfile, "\tmovl %%eax,%d(%%esp)\n", CONTEXTOFFSET(Esp) );

    fprintf( outfile, "\tcall " PREFIX "RELAY_CallFrom32Regs\n" );

    /* Restore the context structure */

    fprintf( outfile, "\tfrstor %d(%%esp)\n", CONTEXTOFFSET(FloatSave) );

    /* Store %eip value onto the new stack */

    fprintf( outfile, "\tmovl %d(%%esp),%%eax\n", CONTEXTOFFSET(Eip) );
    fprintf( outfile, "\tmovl %d(%%esp),%%ebx\n", CONTEXTOFFSET(Esp) );
    fprintf( outfile, "\tmovl %%eax,0(%%ebx)\n" );

    /* Restore all registers */

    fprintf( outfile, "\tleal %d(%%esp),%%esp\n",
             sizeof(FLOATING_SAVE_AREA) + 7 * sizeof(DWORD) );
    fprintf( outfile, "\tpopl %%eax\n" );
    fprintf( outfile, "\tmovw %%ax,%%gs\n" );
    fprintf( outfile, "\tpopl %%eax\n" );
    fprintf( outfile, "\tmovw %%ax,%%fs\n" );
    fprintf( outfile, "\tpopl %%eax\n" );
    fprintf( outfile, "\tmovw %%ax,%%es\n" );
    fprintf( outfile, "\tpopl %%eax\n" );
    fprintf( outfile, "\tmovw %%ax,%%ds\n" );

    fprintf( outfile, "\tpopl %%edi\n" );
    fprintf( outfile, "\tpopl %%esi\n" );
    fprintf( outfile, "\tpopl %%ebx\n" );
    fprintf( outfile, "\tpopl %%edx\n" );
    fprintf( outfile, "\tpopl %%ecx\n" );
    fprintf( outfile, "\tpopl %%eax\n" );
    fprintf( outfile, "\tpopl %%ebp\n" );
    fprintf( outfile, "\tleal 8(%%esp),%%esp\n" );  /* skip %eip and %cs */
    fprintf( outfile, "\tpopfl\n" );
    fprintf( outfile, "\tpopl %%esp\n" );
    fprintf( outfile, "\tret\n" );
}


/*******************************************************************
 *         BuildSpec
 *
 * Build the spec files
 */
static int BuildSpec( FILE *outfile, int argc, char *argv[] )
{
    int i;
    for (i = 2; i < argc; i++)
        if (BuildSpecFile( outfile, argv[i] ) < 0) return -1;
    return 0;
}


/*******************************************************************
 *         BuildCallFrom16
 *
 * Build the 16-bit-to-Wine callbacks
 */
static int BuildCallFrom16( FILE *outfile, char * outname, int argc, char *argv[] )
{
    int i;
    char buffer[1024];

    /* File header */

    fprintf( outfile, "/* File generated automatically. Do not edit! */\n\n" );
    fprintf( outfile, "\t.text\n" );

#ifdef USE_STABS
    fprintf( outfile, "\t.file\t\"%s\"\n", outname );
    getcwd(buffer, sizeof(buffer));

    /*
     * The stabs help the internal debugger as they are an indication that it
     * is sensible to step into a thunk/trampoline.
     */
    fprintf( outfile, ".stabs \"%s/\",100,0,0,Code_Start\n", buffer);
    fprintf( outfile, ".stabs \"%s\",100,0,0,Code_Start\n", outname);
    fprintf( outfile, "\t.text\n" );
    fprintf( outfile, "\t.align 4\n" );
    fprintf( outfile, "Code_Start:\n\n" );
#endif

    /* Build the callback functions */

    for (i = 2; i < argc; i++) BuildCallFrom16Func( outfile, argv[i] );

    /* Output the argument debugging strings */

    if (debugging)
    {
        fprintf( outfile, "/* Argument strings */\n" );
        for (i = 2; i < argc; i++)
        {
            fprintf( outfile, "Profile_%s:\n", argv[i] );
            fprintf( outfile, "\t.ascii \"%s\\0\"\n", argv[i] + 5 );
        }
    }

#ifdef USE_STABS
    fprintf( outfile, "\t.text\n");
    fprintf( outfile, "\t.stabs \"\",100,0,0,.Letext\n");
    fprintf( outfile, ".Letext:\n");
#endif

    return 0;
}


/*******************************************************************
 *         BuildCallTo16
 *
 * Build the Wine-to-16-bit callbacks
 */
static int BuildCallTo16( FILE *outfile, char * outname, int argc, char *argv[] )
{
    char buffer[1024];
    FILE *infile;

    if (argc > 2)
    {
        infile = fopen( argv[2], "r" );
        if (!infile)
        {
            perror( argv[2] );
            exit( 1 );
        }
    }
    else infile = stdin;

    /* File header */

    fprintf( outfile, "/* File generated automatically. Do not edit! */\n\n" );
    fprintf( outfile, "\t.text\n" );

#ifdef USE_STABS
    fprintf( outfile, "\t.file\t\"%s\"\n", outname );
    getcwd(buffer, sizeof(buffer));

    /*
     * The stabs help the internal debugger as they are an indication that it
     * is sensible to step into a thunk/trampoline.
     */
    fprintf( outfile, ".stabs \"%s/\",100,0,0,Code_Start\n", buffer);
    fprintf( outfile, ".stabs \"%s\",100,0,0,Code_Start\n", outname);
    fprintf( outfile, "\t.text\n" );
    fprintf( outfile, "\t.align 4\n" );
    fprintf( outfile, "Code_Start:\n\n" );
#endif

    fprintf( outfile, "\t.globl " PREFIX "CALLTO16_Start\n" );
    fprintf( outfile, PREFIX "CALLTO16_Start:\n" );

    /* Build the callback functions */

    while (fgets( buffer, sizeof(buffer), infile ))
    {
        if (strstr( buffer, "### start build ###" )) break;
    }
    while (fgets( buffer, sizeof(buffer), infile ))
    {
        char *p = strstr( buffer, "CallTo16_" );
        if (p)
        {
            char *profile = p + strlen( "CallTo16_" );
            p = profile;
            while ((*p == '_') || isalpha(*p)) p++;
            *p = '\0';
            BuildCallTo16Func( outfile, profile );
        }
        if (strstr( buffer, "### stop build ###" )) break;
    }

    /* Output the 16-bit return code */

    BuildRet16Func( outfile );

    fprintf( outfile, "\t.globl " PREFIX "CALLTO16_End\n" );
    fprintf( outfile, PREFIX "CALLTO16_End:\n" );

#ifdef USE_STABS
    fprintf( outfile, "\t.text\n");
    fprintf( outfile, "\t.stabs \"\",100,0,0,.Letext\n");
    fprintf( outfile, ".Letext:\n");
#endif

    fclose( infile );
    return 0;
}


/*******************************************************************
 *         BuildCall32
 *
 * Build the 32-bit callbacks
 */
static int BuildCall32( FILE *outfile, char * outname )
{
    char buffer[1024];

    /* File header */

    fprintf( outfile, "/* File generated automatically. Do not edit! */\n\n" );
    fprintf( outfile, "\t.text\n" );

#ifdef USE_STABS
    fprintf( outfile, "\t.file\t\"%s\"\n", outname );
    getcwd(buffer, sizeof(buffer));

    /*
     * The stabs help the internal debugger as they are an indication that it
     * is sensible to step into a thunk/trampoline.
     */
    fprintf( outfile, ".stabs \"%s/\",100,0,0,Code_Start\n", buffer);
    fprintf( outfile, ".stabs \"%s\",100,0,0,Code_Start\n", outname);
    fprintf( outfile, "\t.text\n" );
    fprintf( outfile, "\t.align 4\n" );
    fprintf( outfile, "Code_Start:\n" );
#endif

    /* Build the 32-bit large stack callback */

    BuildCallTo32LargeStack( outfile );

    /* Build the register callback function */

    BuildCallFrom32Regs( outfile );

#ifdef USE_STABS
    fprintf( outfile, "\t.text\n");
    fprintf( outfile, "\t.stabs \"\",100,0,0,.Letext\n");
    fprintf( outfile, ".Letext:\n");
#endif

    return 0;
}


/*******************************************************************
 *         usage
 */
static void usage(void)
{
    fprintf( stderr,
             "usage: build [-o outfile] -spec SPECNAMES\n"
             "       build [-o outfile] -callfrom16 FUNCTION_PROFILES\n"
             "       build [-o outfile] -callto16 FUNCTION_PROFILES\n"
             "       build [-o outfile] -call32\n" );
    exit(1);
}


/*******************************************************************
 *         main
 */
int main(int argc, char **argv)
{
    char *outname = NULL;
    FILE *outfile = stdout;
    int res = -1;

    if (argc < 2) usage();

    if (!strcmp( argv[1], "-o" ))
    {
        outname = argv[2];
        argv += 2;
        argc -= 2;
        if (argc < 2) usage();
        if (!(outfile = fopen( outname, "w" )))
        {
            fprintf( stderr, "Unable to create output file '%s'\n", outname );
            exit(1);
        }
    }

    if (!strcmp( argv[1], "-spec" ))
        res = BuildSpec( outfile, argc, argv );
    else if (!strcmp( argv[1], "-callfrom16" ))
        res = BuildCallFrom16( outfile, outname, argc, argv );
    else if (!strcmp( argv[1], "-callto16" ))
        res = BuildCallTo16( outfile, outname, argc, argv );
    else if (!strcmp( argv[1], "-call32" ))
        res = BuildCall32( outfile, outname );
    else
    {
        fclose( outfile );
        unlink( outname );
        usage();
    }

    fclose( outfile );
    if (res < 0)
    {
        unlink( outname );
        return 1;
    }
    return 0;
}
