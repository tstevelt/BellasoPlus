/*----------------------------------------------------------------------------
	Program : BellasoPlus.c
	Author  : Tom Stevelt
	Date    : May 2024
	Synopsis: Added digits and some punctuation to standard Bellaso cipher.

	https://interestingengineering.com/innovation/11-cryptographic-methods-that-marked-history-from-the-caesar-cipher-to-enigma-code-and-beyond
	https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher

	Who		Date		Modification
	---------------------------------------------------------------------

----------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------
    BellasoPlus

    Copyright (C)  2024 Tom Stevelt

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
---------------------------------------------------------------------------*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<ctype.h>
#include	<errno.h>

#include	"shslib.h"

/*----------------------------------------------------------
	26 letters + 10 digits + sp . , ? !
----------------------------------------------------------*/
#define		NUMCHAR		(26+10+5)
#define		MODE_ENCRYPT		1
#define		MODE_DECRYPT		2

typedef struct
{
	char	RowChar;
	char	Letters[NUMCHAR];
} RECORD;

static	RECORD	*Array;

static	char	*Characters = " !,.0123456789?ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static	int		RunMode;
static	char	*keyword, *ifn, *ofn;
static	int		Debug = 0;
static	int		Table = 0;

static void Usage ()
{
	printf ( "USAGE: BellasoPlus {-e|-d} keyword infile outfile [options]\n" );
	printf ( "Options:\n" );
	printf ( " -v  = verbose\n" );
	printf ( " -t  = print table\n" );
	exit ( 1 );
}

void getargs ( int argc, char *argv[] )
{
	int		xa;

	if ( argc < 5 )
	{
		Usage ();
	}

	for ( xa = 1; xa < argc; xa++ )
	{
		if ( xa + 3 < argc && strcmp ( argv[xa], "-e" ) == 0 )
		{
			RunMode = MODE_ENCRYPT;
			keyword = argv[++xa];
			ifn     = argv[++xa];
			ofn     = argv[++xa];
			}
		else if ( xa + 3 < argc && strcmp ( argv[xa], "-d" ) == 0 )
		{
			RunMode = MODE_DECRYPT;
			keyword = argv[++xa];
			ifn     = argv[++xa];
			ofn     = argv[++xa];
		}
		else if ( strcmp ( argv[xa], "-v" ) == 0 )
		{
			Debug = 1;
		}
		else if ( strcmp ( argv[xa], "-t" ) == 0 )
		{
			Table = 1;
		}
		else
		{
			Usage ();
		}

	}
}

static int cmpcol ( char *a, char *b )
{
	if ( *a < *b )
	{
		return ( -1 );
	}
	if ( *a > *b )
	{
		return ( 1 );
	}
	return ( 0 );
}


static int cmprow ( RECORD *a, RECORD *b )
{
	if ( a->RowChar < b->RowChar )
	{
		return ( -1 );
	}
	if ( a->RowChar > b->RowChar )
	{
		return ( 1 );
	}
	return ( 0 );
}

static void PrintArray ()
{
	printf ( "  " );
	for ( int col = 0; col < NUMCHAR; col++ )
	{
		printf ( "%c", Characters[col] );
	}
	printf ( "\n" );

	for ( int row = 0; row < NUMCHAR; row++ )
	{
		printf ( "%c ", Array[row].RowChar );
		for ( int col = 0; col < NUMCHAR; col++ )
		{
			printf ( "%c", Array[row].Letters[col] );
		}
		printf ( "\n" );
	}
}

static void MakeArray ()
{
	if (( Array = calloc ( NUMCHAR, sizeof(RECORD) )) == NULL )
	{
		printf ( "calloc failed, %s\n", strerror(errno) );
		exit ( 1 );
	}

	int	offset = 0;
	for ( int row = 0; row < NUMCHAR; row++ )
	{
		Array[row].RowChar = Characters[row];
		for ( int col = 0; col < NUMCHAR; col++ )
		{
			int		pick;

			if ( col+offset < NUMCHAR )
			{
				pick = col+offset;
			}
			else
			{
				pick = col+offset-NUMCHAR;
			}

			if ( pick < NUMCHAR )
			{
				Array[row].Letters[col] = Characters[pick];
			}
		}
		offset++;
	}

	if ( Table )
	{
		PrintArray ();
	}
}

int main (int argc, char *argv[] )
{
	int		keywordlen, keywordndx;
	FILE	*ifp, *ofp;
	char	xbuffer[1024];
	int		lineno;
	RECORD	RowKey, *RowPtr;
	char	*ColPtr;

	getargs ( argc, argv );

	for ( int ndx = 0; ndx < strlen(keyword); ndx++ )
	{
		if ( keyword[ndx] >= 'a' && keyword[ndx] <= 'z' )
		{
			keyword[ndx] = toupper ( keyword[ndx] );
		}

		if ( strchr ( Characters, keyword[ndx] ) == NULL )
		{
			printf ( "Invalid keyword, should only contain %s\n", Characters );
			exit ( 1 );
		}
	}
	keywordlen = strlen ( keyword );

	if ( access ( ifn, F_OK ) != 0 )
	{
		printf ( "Cannot access input file %s\n", ifn );
		exit ( 1 );
	}

#ifdef DIE_ON_EXIST
	if ( access ( ofn, F_OK ) == 0 )
	{
		printf ( "Output file %s exists! Program canceled!\n", ofn );
		exit ( 1 );
	}
#endif

	if (( ifp = fopen ( ifn, "r" )) == (FILE *)0 )
	{
		printf ( "Cannot open sorted file %s\n", ifn );
		exit ( 1 );
	}

	if (( ofp = fopen ( ofn, "w" )) == (FILE *)0 )
	{
		printf ( "Cannot created output file %s\n", ofn );
		exit ( 1 );
	}

	MakeArray ();
	
	lineno = 0;
	keywordndx = 0;
	int	Offset;
	while ( fgets ( xbuffer, sizeof(xbuffer), ifp ) != (char *)0 )
	{
		lineno++;

		if ( RunMode == MODE_ENCRYPT )
		{
			for ( int xb = 0; xb < strlen(xbuffer); xb++ )
			{
				switch ( xbuffer[xb] )
				{
					case '\n':
					case '\r':
						fprintf ( ofp, "%c", xbuffer[xb] );
						continue;
				}

				RowKey.RowChar = keyword[keywordndx];
				if (( RowPtr = bsearch ( &RowKey, Array, NUMCHAR, sizeof(RECORD), (int(*)()) cmprow )) == NULL )
				{
					printf ( "Cannot find row [%c]\n", RowKey.RowChar );
					exit ( 1 );
				}

				char PlainLetter = toupper(xbuffer[xb]);
				if (( ColPtr = bsearch ( &PlainLetter, Characters, NUMCHAR, sizeof(char), (int(*)()) cmpcol )) == NULL )
				{
					fprintf ( ofp, "_" );
					continue;
				}
				else
				{
					Offset = ColPtr - Characters;
					fprintf ( ofp, "%c", RowPtr->Letters[Offset] );
				}

				if ( Debug )
				{
					printf ( "%c %c %c\n", RowKey.RowChar, PlainLetter, RowPtr->Letters[Offset] );
				}
 
				keywordndx++;
				if ( keywordndx == keywordlen )
				{
					keywordndx = 0;
				}
			}
		}
		else
		{
			for ( int xb = 0; xb < strlen(xbuffer); xb++ )
			{
				switch ( xbuffer[xb] )
				{
					case '\n':
					case '\r':
					case '_':
						fprintf ( ofp, "%c", xbuffer[xb] );
						continue;
				}

				RowKey.RowChar = keyword[keywordndx];
				if (( RowPtr = bsearch ( &RowKey, Array, NUMCHAR, sizeof(RECORD), (int(*)()) cmprow )) == NULL )
				{
					printf ( "Cannot find row [%c]\n", RowKey.RowChar );
					exit ( 1 );
				}

				char CodeLetter = toupper(xbuffer[xb]);
				int	ColNdx;
				for ( ColNdx = 0; ColNdx < NUMCHAR; ColNdx++ )
				{
					if ( CodeLetter == RowPtr->Letters[ColNdx] )
					{
						break;
					}
				}
				
				if ( ColNdx >= NUMCHAR )
				{
					printf ( "Cannot find %c in row %c in table\n", CodeLetter, RowKey.RowChar );
					exit ( 1 );
				}	
 
 				fprintf ( ofp, "%c", Characters[ColNdx] );


				keywordndx++;
				if ( keywordndx == keywordlen )
				{
					keywordndx = 0;
				}
			}
		}
	}

	fclose ( ifp );
	fclose ( ofp );

    return 0;
}
