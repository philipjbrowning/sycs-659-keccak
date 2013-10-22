/*
KeccakTools

The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <iomanip>
#include <sstream>
#include <vector>
#include "sponge.h"

using namespace std;

SpongeException::SpongeException(const string& aReason)
    : reason(aReason)
{
}


Sponge::Sponge(const Transformation *aF, const PaddingRule *aPad, unsigned int aRate)
    : f(aF), pad(aPad), rate(aRate), squeezing(false), absorbQueue(rate)
{
    // *************************************************************************
    cout << "    a. OBJECT CREATED: Sponge\n";
    // *************************************************************************
    unsigned int width = f->getWidth();
    if (rate <= 0)
        throw SpongeException("The requested rate must be strictly positive.");
    if (rate > width)
        throw SpongeException("The requested rate is too large when using this function.");
    if (!pad->isRateValid(rate))
        throw SpongeException("The requested rate is incompatible with the padding rule.");
    capacity = width-rate;
    // *************************************************************************
    cout << "       - width=" << width << "\n";
    cout << "       - capacity=" << capacity << "\n";
    cout << "       - rate=" << rate << "\n";
    // *************************************************************************
    state.reset(new UINT8[(width+7)/8]);
    for(unsigned int i=0; i<(width+7)/8; i++)
        state.get()[i] = 0;
}

unsigned int Sponge::getCapacity()
{
    return capacity;
}

unsigned int Sponge::getRate()
{
    return rate;
}

void Sponge::reset()
{
    squeezing = false;
    unsigned int width = f->getWidth();
    for(unsigned int i=0; i<(width+7)/8; i++)
        state.get()[i] = 0;
    absorbQueue.clear();
    squeezeBuffer.clear();
}

void Sponge::absorb(const UINT8 *input, unsigned int lengthInBits)
{
    // *************************************************************************
    cout << "    d. Sponge::absorb(UNIT8 *input, lengthInBits=" << lengthInBits << ")\n";
    // *************************************************************************
    unsigned int lengthInBytes = (lengthInBits+7)/8;
    vector<UINT8> inputAsVector(input, input+lengthInBytes);
    absorb(inputAsVector, lengthInBits);
}

void Sponge::absorb(const vector<UINT8>& input, unsigned int lengthInBits)
{
    // *************************************************************************
    cout << "    e. Sponge::absorb(vector<UINT8>& input, lengthInBits=" << lengthInBits << ")\n";
    // *************************************************************************
    if (lengthInBits == 0)
        return;
    unsigned int lengthInBytes = (lengthInBits+7)/8;
    cout << "       - input.size = " << input.size() << endl;
    cout << "       - lengthInBytes = " << lengthInBytes << endl;
    cout << "       - lengthInBits = " << lengthInBits << endl;
    if (input.size() < lengthInBytes)
        throw SpongeException("The given input length is inconsistent.");
    if (squeezing) {
        throw SpongeException("The absorbing phase is over.");
        cout << "       - The absorbing phase is over.\n";
    }
    else
        cout << "       - The absorbing phase is NOT over yet.\n";
    absorbQueue.append(input, lengthInBits);
    while(absorbQueue.firstBlockIsWhole()) {
        cout << "       - firstBlock is whole.\n";
        absorbBlock(absorbQueue.firstBlock());
        absorbQueue.removeFirstBlock();
    }
}

void Sponge::absorbBlock(const vector<UINT8>& block)
{
    cout << "        Sponge::absorbBlock(const vector<UINT8>& block)\n";
    cout << "        - block.size() = " << block.size() << endl;
    for(vector<UINT8>::size_type i=0; i<block.size(); ++i) {
        state.get()[i] ^= block[i];
        // cout << "        - " << block[i] << endl;
    }
    (*f)(state.get());
}

void Sponge::squeeze(UINT8 *output, unsigned int desiredLengthInBits)
{
    // *************************************************************************
    cout << "    f. Sponge::squeeze(UINT8 *output, desiredLengthInBits=" << desiredLengthInBits << ")\n";
    // *************************************************************************
    vector<UINT8> outputAsVector;
    squeeze(outputAsVector, desiredLengthInBits);
    for(unsigned int i=0; i<outputAsVector.size(); i++)
        output[i] = outputAsVector[i];
}

void Sponge::squeeze(vector<UINT8>& output, unsigned int desiredLengthInBits)
{
    // *************************************************************************
    cout << "    g. Sponge::squeeze(vector<UINT8>& output, desiredLengthInBits=" << desiredLengthInBits << ")\n";
    // *************************************************************************
    if (!squeezing)
        flushAndSwitchToSqueezingPhase();
    if ((rate % 8) == 0) {
        if ((desiredLengthInBits % 8) != 0)
            throw SpongeException("The desired output length must be a multiple of 8.");
        unsigned int desiredLengthInBytes = desiredLengthInBits / 8;
        while(desiredLengthInBytes > 0) {
            if (squeezeBuffer.size() == 0)
                squeezeIntoBuffer();
            while((desiredLengthInBytes > 0) && (squeezeBuffer.size() > 0)) {
                output.push_back(squeezeBuffer.front());
                desiredLengthInBytes--;
                squeezeBuffer.pop_front();
            }
        }
    }
    else {
        if (desiredLengthInBits != rate)
            throw SpongeException("The desired output length must be equal to the rate.");
        if (squeezeBuffer.size() == 0)
            squeezeIntoBuffer();
        while(squeezeBuffer.size() > 0) {
            output.push_back(squeezeBuffer.front());
            squeezeBuffer.pop_front();
        }
    }
}

void Sponge::squeezeIntoBuffer()
{
    (*f)(state.get());
    fromStateToSqueezeBuffer();
}

void Sponge::fromStateToSqueezeBuffer()
{
    for(unsigned int i=0; i<rate/8; ++i)
        squeezeBuffer.push_back(state.get()[i]);
    if ((rate % 8) != 0) {
        UINT8 lastByte = (state.get())[rate/8];
        UINT8 mask = (1 << (rate % 8)) - 1;
        squeezeBuffer.push_back(lastByte & mask);
    }
}

void Sponge::flushAndSwitchToSqueezingPhase()
{
    pad->pad(rate, absorbQueue);
    while(absorbQueue.firstBlockIsWhole()) {
        absorbBlock(absorbQueue.firstBlock());
        absorbQueue.removeFirstBlock();
    }
    squeezing = true;
    fromStateToSqueezeBuffer();
}

string Sponge::getDescription() const
{
    stringstream a;
    a << "Sponge[f=" << (*f) << ", pad=" << (*pad)
        << ", r=" << dec << rate 
        << ", c=" << capacity << "]";
    return a.str();
}

void Sponge::printState()
{
    for (unsigned int i=0; i<(capacity+rate)/8; i++) {
        printf("[ %02X ] ", state.get()[i]);
        if (i%5 == 4) {
            cout << endl;
        }
        if (i%25 == 24) {
            cout << endl;
        }
    }
}

ostream& operator<<(ostream& a, const Sponge& sponge)
{
    return a << sponge.getDescription();
}
