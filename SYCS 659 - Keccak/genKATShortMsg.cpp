/*
KeccakTools

The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

This code is based on genKAT.c by NIST.
*/

#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <ctype.h>

#include "duplex.h"
#include "Keccak.h"

#define MAX_MARKER_LEN      50
#define SUBMITTER_INFO_LEN  128

typedef enum { KAT_SUCCESS = 0, KAT_FILE_OPEN_ERROR = 1, KAT_HEADER_ERROR = 2, KAT_DATA_ERROR = 3, KAT_HASH_ERROR = 4 } STATUS_CODES;
typedef unsigned char BitSequence;

STATUS_CODES genShortMsg(unsigned int rate, unsigned int capacity, int outputLength, const std::string& suffix, bool fixedOutputLength = false);
int     FindMarker(FILE *infile, const char *marker);
int     ReadHex(FILE *infile, BitSequence *A, int Length, const char *str);
void    fprintBstr(FILE *fp, const char *S, BitSequence *A, int L);

#define SqueezingOutputLength 4096

void genKATShortMsg_main()
{
    std::cout << "[1] FUNCTION: genKATShortMsg_main()\n";
    genShortMsg(1024,  576, 4096, "0");
    /*
    genShortMsg(1152,  448,  224, "224", true);
    genShortMsg(1088,  512,  256, "256", true);
    genShortMsg( 832,  768,  384, "384", true);
    genShortMsg( 576, 1024,  512, "512", true);
    genShortMsg(1344,  256, 4096, "r1344c256");
    genShortMsg( 256,  544,  544, "r256c544");
    genShortMsg( 512,  288,  512, "r512c288");
    genShortMsg( 544,  256,  544, "r544c256");
    genShortMsg( 128,  272,  272, "r128c272");
    genShortMsg( 144,  256,  256, "r144c256");
    */
    // genShortMsg(  40,   160,  160, "r40c160");
    
}

STATUS_CODES genSpongeKAT(Sponge& sponge, const std::string& suffix);

void genSpongeKAT()
{
    std::cout << "*-- genSpongeKAT() --------------------------------------*\n";
    {
        KeccakF keccakF(1600);
        //OldDiversifiedKeccakPadding pad(0);
        MultiRatePadding pad;
        Sponge sponge(&keccakF, &pad, 1024);
        genSpongeKAT(sponge, "r1024c576");
    }
}

STATUS_CODES genDuplexKAT(Duplex& duplex, const std::string& suffix);

void genDuplexKAT()
{
    std::cout << "*-- genDuplexKAT() --------------------------------------*\n";
    for(unsigned int rate=1024; rate<=1032; rate++) {
        KeccakF keccakF(1600);
        MultiRatePadding pad;
        Duplex duplex(&keccakF, &pad, rate);
        std::stringstream str;
        str << "r" << dec << rate << "c" << (1600-rate);
        genDuplexKAT(duplex, str.str());
    }
    {
        KeccakF keccakF(1600);
        MultiRatePadding pad;
        Duplex duplex(&keccakF, &pad, 1346);
        genDuplexKAT(duplex, "r1346c254");
    }
    {
        KeccakF keccakF(800);
        MultiRatePadding pad;
        Duplex duplex(&keccakF, &pad, 546);
        genDuplexKAT(duplex, "r546c254");
    }
    {
        KeccakF keccakF(400);
        MultiRatePadding pad;
        Duplex duplex(&keccakF, &pad, 146);
        genDuplexKAT(duplex, "r146c254");
    }
    {
        KeccakF keccakF(200);
        MultiRatePadding pad;
        Duplex duplex(&keccakF, &pad, 42);
        genDuplexKAT(duplex, "r42c158");
    }
}

void fromNISTConventionToInternalConvention(BitSequence *Msg, int msglen)
{
    // *************************************************************************
    std::cout << "    c. Convert fromNISTConventionToInternalConvention()\n";
    // *************************************************************************
    if ((msglen % 8) != 0) {
        Msg[msglen/8] >>= 8 - (msglen % 8);
    }
}

STATUS_CODES genShortMsg(unsigned int rate, unsigned int capacity, int outputLength, const std::string& suffix, bool fixedOutputLength)
{
    // *************************************************************************
    std::cout << "[2] FUNCTION: genShortMsg(rate=" << rate << ", capacity=" << capacity << ", outputLength=" << outputLength << ", suffix=" << suffix << ", fixedOutputLength=";
    if (fixedOutputLength == true) {
        std::cout << "true";
    } else {
        std::cout << "false";
    }
    std::cout << ")\n";
    // *************************************************************************
    char        line[SUBMITTER_INFO_LEN];
    int         msglen, msgbytelen, done;
    BitSequence Msg[256];
    BitSequence Squeezed[SqueezingOutputLength/8];
    FILE        *fp_in, *fp_out;

    if ( (fp_in = fopen("ShortTweet72KAT.txt", "r")) == NULL ) {
        printf("Couldn't open <ShortMsgKAT.txt> for read\n");
        return KAT_FILE_OPEN_ERROR;
    }
    
    string fileName = std::string("ShortTweet72KAT_") + suffix + std::string(".txt");
    if ( (fp_out = fopen(fileName.c_str(), "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fileName.c_str());
        return KAT_FILE_OPEN_ERROR;
    }
    fprintf(fp_out, "# %s\n", fileName.c_str());
    if ( FindMarker(fp_in, "# Algorithm Name:") ) {
        fscanf(fp_in, "%[^\n]\n", line);
        fprintf(fp_out, "# Algorithm Name:%s\n", line);
    }
    else {
        printf("genShortMsg: Couldn't read Algorithm Name\n");
        return KAT_HEADER_ERROR;
    }
    if ( FindMarker(fp_in, "# Principal Submitter:") ) {
        fscanf(fp_in, "%[^\n]\n", line);
        fprintf(fp_out, "# Principal Submitter:%s\n", line);
    }
    else {
        printf("genShortMsg: Couldn't read Principal Submitter\n");
        return KAT_HEADER_ERROR;
    }
    
    done = 0;
    do {
        if ( FindMarker(fp_in, "Len = ") )
            fscanf(fp_in, "%d", &msglen);
        else {
            done = 1;
            break;
        }
        msgbytelen = (msglen+7)/8;

        if ( !ReadHex(fp_in, Msg, msgbytelen, "Msg = ") ) {
            printf("ERROR: unable to read 'Msg' from <ShortTweet72KAT.txt>\n");
            return KAT_DATA_ERROR;
        }
        fprintf(fp_out, "\nLen = %d\n", msglen);
        fprintBstr(fp_out, "Msg = ", Msg, msgbytelen);
        
        // ********************************************************************* BASE KECCAK ALGORITHM
        cout << "[3] SEQUENCE: Keccak Algorithm Starting\n";
        Keccak keccak(rate, capacity);
        cout << "    - keccak.getDescription=" << keccak.getDescription() << "\n";
        fromNISTConventionToInternalConvention(Msg, msglen);
        cout << endl << "+----------------------------------+\n";
        cout << "| Keccak Sponge Initial State      |\n";
        cout << "+----------------------------------+\n\n";
        keccak.printState();
        
        keccak.absorb(Msg, msglen);
        cout << endl << "+----------------------------------+\n";
        cout << "| Keccak Sponge After Absorb State |" << endl;
        cout << "+----------------------------------+\n\n";
        keccak.printState();
        
        keccak.squeeze(Squeezed, outputLength);
        cout << endl << "+----------------------------------+\n";
        cout << "| Keccak Sponge Final State        |" << endl;
        cout << "+----------------------------------+\n\n";
        keccak.printState();
        cout << "[4] SEQUENCE: Keccak Algorithm Finished\n";
        // ********************************************************************* BASE KECCAK ALGORITHM
        if (fixedOutputLength)
            fprintBstr(fp_out, "MD = ", Squeezed, outputLength/8);
        else
            fprintBstr(fp_out, "Squeezed = ", Squeezed, outputLength/8);
    } while ( !done );
    printf("[5] finished ShortTweet72KAT for <%s>\n", suffix.c_str());
    
    fclose(fp_in);
    fclose(fp_out);
    
    return KAT_SUCCESS;
}

STATUS_CODES genSpongeKAT(Sponge& sponge, const std::string& suffix)
{
    std::cout << "*-- genSpongeKAT() --*\n";
    int absorbedLen, absorbedByteLen, squeezedLen, squeezedByteLen, done;
    BitSequence absorbed[512];
    BitSequence squeezed[512];
    FILE *fp_in, *fp_out;

    if ( (fp_in = fopen("SpongeKAT.txt", "r")) == NULL ) {
        printf("Couldn't open <SpongeKAT.txt> for read\n");
        return KAT_FILE_OPEN_ERROR;
    }
    
    string fileName = std::string("SpongeKAT_") + suffix + std::string(".txt");
    if ( (fp_out = fopen(fileName.c_str(), "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fileName.c_str());
        return KAT_FILE_OPEN_ERROR;
    }
    fprintf(fp_out, "# %s\n", fileName.c_str());
    string description = sponge.getDescription();
    fprintf(fp_out, "# Algorithm: %s\n", description.c_str());
    
    done = 0;
    squeezedLen = 4096;
    squeezedByteLen = (squeezedLen+7)/8;
    do {
        if ( FindMarker(fp_in, "AbsorbedLen = ") )
            fscanf(fp_in, "%d", &absorbedLen);
        else {
            done = 1;
            break;
        }
        absorbedByteLen = (absorbedLen+7)/8;

        if ( !ReadHex(fp_in, absorbed, absorbedByteLen, "Absorbed = ") ) {
            printf("ERROR: unable to read 'Absorbed' from <SpongeKAT.txt>\n");
            return KAT_DATA_ERROR;
        }
        fprintf(fp_out, "\nAbsorbedLen = %d\n", absorbedLen);
        fprintBstr(fp_out, "Absorbed = ", absorbed, absorbedByteLen);
        sponge.reset();
        sponge.absorb(absorbed, absorbedLen);
        sponge.squeeze(squeezed, squeezedLen);
        fprintf(fp_out, "SqueezedLen = %d\n", squeezedLen);
        fprintBstr(fp_out, "Squeezed = ", squeezed, squeezedByteLen);
    } while ( !done );
    printf("finished SpongeKAT for <%s>\n", suffix.c_str());
    
    fclose(fp_in);
    fclose(fp_out);
    
    return KAT_SUCCESS;
}

STATUS_CODES genDuplexKAT(Duplex& duplex, const std::string& suffix)
{
    std::cout << "*-- genDuplexKAT()\n";
    int inLen, inByteLen, outLen, outByteLen, done;
    BitSequence in[256];
    BitSequence out[256];
    FILE *fp_in, *fp_out;

    if ( (fp_in = fopen("DuplexKAT.txt", "r")) == NULL ) {
        printf("Couldn't open <DuplexKAT.txt> for read\n");
        return KAT_FILE_OPEN_ERROR;
    }
    
    string fileName = std::string("DuplexKAT_") + suffix + std::string(".txt");
    if ( (fp_out = fopen(fileName.c_str(), "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fileName.c_str());
        return KAT_FILE_OPEN_ERROR;
    }
    fprintf(fp_out, "# %s\n", fileName.c_str());
    string description = duplex.getDescription();
    fprintf(fp_out, "# Algorithm: %s\n", description.c_str());
    
    done = 0;
    outLen = duplex.getMaximumOutputLength();
    outByteLen = (outLen+7)/8;
    do {
        if ( FindMarker(fp_in, "InLen = ") )
            fscanf(fp_in, "%d", &inLen);
        else {
            done = 1;
            break;
        }
        inByteLen = (inLen+7)/8;

        if ( !ReadHex(fp_in, in, inByteLen, "In = ") ) {
            printf("ERROR: unable to read 'In' from <DuplexKAT.txt>\n");
            return KAT_DATA_ERROR;
        }
        if (inLen <= duplex.getMaximumInputLength()) {
            fprintf(fp_out, "\nInLen = %d\n", inLen);
            fprintBstr(fp_out, "In = ", in, inByteLen);
            duplex.duplexing(in, inLen, out, outLen);
            fprintf(fp_out, "OutLen = %d\n", outLen);
            fprintBstr(fp_out, "Out = ", out, outByteLen);
        }
    } while ( !done );
    printf("finished DuplexKAT for <%s>\n", suffix.c_str());
    
    fclose(fp_in);
    fclose(fp_out);
    
    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
    std::cout << "    - FindMarker()\n";
    char    line[MAX_MARKER_LEN];
    int     i, len;

    len = (int)strlen(marker);
    if ( len > MAX_MARKER_LEN-1 )
        len = MAX_MARKER_LEN-1;

    for ( i=0; i<len; i++ )
        if ( (line[i] = fgetc(infile)) == EOF )
            return 0;
    line[len] = '\0';

    while ( 1 ) {
        if ( !strncmp(line, marker, len) )
            return 1;

        for ( i=0; i<len-1; i++ )
            line[i] = line[i+1];
        if ( (line[len-1] = fgetc(infile)) == EOF )
            return 0;
        line[len] = '\0';
    }

    // shouldn't get here
    return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, BitSequence *A, int Length, const char *str)
{
    std::cout << "    - ReadHex()\n";
    int         i, ch, started;
    BitSequence ich;

    if ( Length == 0 ) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    if ( FindMarker(infile, str) )
        while ( (ch = fgetc(infile)) != EOF ) {
            if ( !isxdigit(ch) ) {
                if ( !started ) {
                    if ( ch == '\n' )
                        break;
                    else
                        continue;
                }
                else
                    break;
            }
            started = 1;
            if ( (ch >= '0') && (ch <= '9') )
                ich = ch - '0';
            else if ( (ch >= 'A') && (ch <= 'F') )
                ich = ch - 'A' + 10;
            else if ( (ch >= 'a') && (ch <= 'f') )
                ich = ch - 'a' + 10;

            for ( i=0; i<Length-1; i++ )
                A[i] = (A[i] << 4) | (A[i+1] >> 4);
            A[Length-1] = (A[Length-1] << 4) | ich;
        }
    else
        return 0;

    return 1;
}

void
fprintBstr(FILE *fp, const char *S, BitSequence *A, int L)
{
    std::cout << "    - fprintBstr()\n";
    int     i;

    fprintf(fp, "%s", S);

    for ( i=0; i<L; i++ )
        fprintf(fp, "%02X", A[i]);

    if ( L == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
