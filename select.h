/*
Copyright (c) 2018 - 2019 Amir Hossein Alikhah Mishamandani

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <inttypes.h>

#ifndef SELECT_H
#define SELECT_H

//the data structure to feed big test vectors
typedef struct ListOfSuperNodes_ {
	unsigned char seed[32];
	unsigned char HashOfPoW[32];
	unsigned char sk[64];
	unsigned char pk[32];
	unsigned char proof[80];
	unsigned char output[64];
} ListOfSuperNodes;

typedef struct ListOfConditions_ {
	uint32_t round;
	int memoryselected_One;
	int memoryselected_Two;
	int bitselected_one;
	int bitselected_two;
	int bit_one_value;
	int bit_two_value;
} ListOfConditions;

typedef struct TempListOfWinners_ {
	unsigned char winner_HashOfPoW[32];
	unsigned char winner_pk[32];
	unsigned char winner_proof[80];
	unsigned char winner_output[64];

} TempListOfWinners;

typedef struct ListOfWinners_ {
	uint32_t Winner_round;
	int Winner_round_memoryselected_One;
	int Winner_round_memoryselected_Two;
	int Winner_round_bitselected_one;
	int Winner_round_bitselected_two;
	int Winner_round_bit_one_value;
	int Winner_round_bit_two_value;
	uint8_t res_winner_list;
	unsigned char winner_HashOfPoW[32];
	unsigned char winner_pk[32];
	unsigned char winner_proof[80];
	unsigned char winner_output[64];

} ListOfWinners;


//the data structure to feed big test vectors
int select(uint8_t listsize, uint8_t Attestors_Required);

#endif