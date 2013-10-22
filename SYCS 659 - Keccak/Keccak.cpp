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

#include <iostream>
#include <sstream>
#include "Keccak.h"

using namespace std;

Keccak::Keccak(unsigned int aRate, unsigned int aCapacity)
    : Sponge(new KeccakF(aRate+aCapacity), new MultiRatePadding(), aRate)
{
    // *************************************************************************
    cout << "    b. OBJECT CREATED: Keccak\n";
    // *************************************************************************
}

Keccak::~Keccak()
{
    // delete f;
    // delete pad;
}

string Keccak::getDescription() const
{
    stringstream a;
    a << "Keccak[r=" << dec << rate << ", c=" << dec << capacity << "]";
    return a.str();
}

void Keccak::printState()
{
    Sponge::printState();
}

ReducedRoundKeccak::ReducedRoundKeccak(unsigned int aRate, unsigned int aCapacity, unsigned int aNrRounds)
    : Sponge(new KeccakF(aRate+aCapacity, aNrRounds), new MultiRatePadding(), aRate),
    nrRounds(aNrRounds)
{
}

ReducedRoundKeccak::~ReducedRoundKeccak()
{
    // delete f;
    // delete pad;
}

string ReducedRoundKeccak::getDescription() const
{
    stringstream a;
    a << "Keccak[r=" << dec << rate << ", c=" << dec << capacity << ", rounds=" << dec << nrRounds << "]";
    return a.str();
}
