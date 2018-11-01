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

#include "select.h"
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <math.h>
#include "convert.h"
#include "vrf.h"
#include "crypto_vrf.h"
#include "sha512EL.h"
#include <bitset>

ListOfSuperNodes mylist[255] = {{0}, {0}, {0}, {0}, {0}, {0}};

ListOfConditions mycondlist = {0, 0, 0, 0, 0, 0, 0};

ListOfWinners mywinnerslist[255] = {0, 0, 0, 0, 0, 0, 0, 0, {0}, {0}, {0}, {0}};

TempListOfWinners mytempwinnerslist[255] = {{0}, {0}, {0}, {0}};

//printing the buffer in HEX
static inline void printhex(const char *label, const unsigned char *c, size_t len){
	size_t i;
	printf("%s", label);
	for (i = 0; i < len; i++){
		printf("%02x", c[i]);
	}
	printf("\n");
}

//printing an array of integers
static inline void printbuff(const char *label, const unsigned char *c, size_t len){
	size_t i;
	printf("%s", label);
	for (i = 0; i < len; i++){
		printf("%" PRIu8 "", c[i]);
	}
	printf("\n");
}

//printing a string 
void printstring(const char *caption,char *m){
	printf("%s%s\n",caption,m);
}

//Generating the random number based on timestamp
int random_int(uint8_t *in) 
{
	struct timespec t;	
	int64_t millitime;
    uint8_t timestamp[8];
	memset(timestamp, 0 , 8);
	
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
    timestamp[0] = rand() % 256;
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);	
    timestamp[1] = rand() % 256;
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
	timestamp[2] = rand() % 256;
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
	timestamp[3] = rand() % 256;
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
	timestamp[4] = rand() % 256;
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
	timestamp[5] = rand() % 256;
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);	
	timestamp[6] = rand() % 256;
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
	timestamp[7] = rand() % 256;
	crypto_hash_sha512(in, timestamp, 8);
}

//Generates the list
void Generate_List(uint8_t listlen){
		
	for(uint8_t counter = 0; counter < listlen; counter++){
		random_int(mylist[counter].seed);
		crypto_vrf_ietfdraft03_keypair_from_seed(mylist[counter].pk, mylist[counter].sk, mylist[counter].seed);
		if (!crypto_vrf_ietfdraft03_is_valid_key(mylist[counter].pk)) {
			printf("Error: generated keypair is not valid\n");
		}
		random_int(mylist[counter].HashOfPoW);
		crypto_vrf_ietfdraft03_prove(mylist[counter].proof, mylist[counter].sk,  mylist[counter].HashOfPoW, sizeof(mylist[counter].HashOfPoW));
		crypto_vrf_ietfdraft03_proof_to_hash(mylist[counter].output, mylist[counter].proof);
		if(!crypto_vrf_ietfdraft03_verify(mylist[counter].output, mylist[counter].pk, mylist[counter].proof,  mylist[counter].HashOfPoW, sizeof(mylist[counter].HashOfPoW))){
			printf("Error: invalid proof\n");
		}
	}	
}

void printmembers(uint8_t listlen){
	printf("\n");
	for(uint8_t counter = 0; counter < listlen; counter++){
		printf("Supernode [%" PRIu8 "]:\n",counter);
		printbuff("seed = ", mylist[counter].seed, 32);
		printbuff("HashOfPoW = ", mylist[counter].HashOfPoW, 32);
		printbuff("sk = ", mylist[counter].sk, 64);
		printbuff("pk = ", mylist[counter].pk, 32);
		printbuff("proof (pi) = ", mylist[counter].proof, 80);
		printbuff("betta (hash) = ", mylist[counter].output, 64);
	}	
}

void printmytempwinnerslist(uint8_t listlen){
	printf("\n");
	for(uint8_t counter = 0; counter < listlen; counter++){
		printf("Candidate Supernode [%" PRIu8 "]:\n",counter);
		printbuff("HashOfPoW = ", mytempwinnerslist[counter].winner_HashOfPoW, 32);
		printbuff("pk = ", mytempwinnerslist[counter].winner_pk, 32);
		printbuff("proof (pi) = ", mytempwinnerslist[counter].winner_proof, 80);
		printbuff("betta (hash) = ", mytempwinnerslist[counter].winner_output, 64);
	}	
}

void printmywinnerslist(uint8_t listlen){
	printf("\n");
	for(uint8_t counter = 0; counter < listlen; counter++){
		printf("Attestor [%" PRIu8 "]:\n",counter+1);
		printf("Round [%" PRIu32 "]:\n",mywinnerslist[counter].Winner_round);
		printf("Index in temp list = [%" PRIu8 "]\n",mywinnerslist[counter].res_winner_list);
		printbuff("HashOfPoW = ", mywinnerslist[counter].winner_HashOfPoW, 32);
		printbuff("pk = ", mywinnerslist[counter].winner_pk, 32);
		printbuff("proof (pi) = ", mywinnerslist[counter].winner_proof, 80);
		printbuff("betta (hash) = ", mywinnerslist[counter].winner_output, 64);
	}	
}

void generate_condition(int memoryselected_One, int memoryselected_Two, int bitselected_one, int bitselected_two, int bit_one_value, int bit_two_value){
	mycondlist = {0, 0, 0, 0, 0};
	struct timespec t;	
	int64_t millitime;
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
    memoryselected_One = rand() % 64;
	
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
    memoryselected_Two = rand() % 64;
	
	if(memoryselected_One == memoryselected_Two){
		while(bitselected_one == bitselected_two){
			clock_gettime(CLOCK_REALTIME, &t);
			millitime = t.tv_nsec;
			srand(millitime);
			memoryselected_Two = rand() % 64;
		}
	}
	
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
    memoryselected_Two = rand() % 64;
	
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
    bitselected_one = rand() % 8;
	
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
    bitselected_two = rand() % 8;
	
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
    bit_one_value = rand() % 2;
	
	clock_gettime(CLOCK_REALTIME, &t);
	millitime = t.tv_nsec;
	srand(millitime);
    bit_two_value = rand() % 2;
	
	if(bitselected_one == bitselected_two){
		while(bitselected_one == bitselected_two){
			clock_gettime(CLOCK_REALTIME, &t);
			millitime = t.tv_nsec;
			srand(millitime);
			bitselected_two = rand() % 8;
		}
	}
}

void generate_List_Of_Winners(uint8_t listlen, uint8_t numberofwinners){
	uint8_t winnertemp = 0;
	uint8_t winner = 0;
	uint8_t counter = 0;
	
	while(winnertemp < numberofwinners){
		generate_condition(mycondlist.memoryselected_One, mycondlist.memoryselected_Two, mycondlist.bitselected_one, mycondlist.bitselected_two, mycondlist.bit_one_value, mycondlist.bit_two_value);
		winnertemp = 0;
		for(counter = 0; counter < listlen; counter++){
			std::bitset<8> b1(mylist[counter].output[mycondlist.memoryselected_One]);
			std::bitset<8> b2(mylist[counter].output[mycondlist.memoryselected_Two]);
			int cond_One = 0;
			int cond_Two = 0;
			if(b1[mycondlist.bitselected_one] == mycondlist.bit_one_value & b1[mycondlist.bitselected_two] == mycondlist.bit_two_value){cond_One = 1;}
			if(b2[mycondlist.bitselected_one] == mycondlist.bit_two_value & b2[mycondlist.bitselected_two] == mycondlist.bit_one_value){cond_Two = 1;}
			
			if(cond_One == 1 && cond_Two == 1){
				memcpy(mytempwinnerslist[winnertemp].winner_HashOfPoW, mylist[counter].HashOfPoW,32);
				memcpy(mytempwinnerslist[winnertemp].winner_pk, mylist[counter].pk,32);
				memcpy(mytempwinnerslist[winnertemp].winner_proof, mylist[counter].proof,80);
				memcpy(mytempwinnerslist[winnertemp].winner_output, mylist[counter].output,64);
				winnertemp++;
			}
		}
	}
	
	if(winnertemp == numberofwinners){
		for(counter = 0; counter <= numberofwinners; counter++){
				mywinnerslist[counter].res_winner_list = counter;
				mywinnerslist[counter].Winner_round_memoryselected_One = mycondlist.memoryselected_One;
				mywinnerslist[counter].Winner_round_memoryselected_Two = mycondlist.memoryselected_Two;
				mywinnerslist[counter].Winner_round_bitselected_one = mycondlist.bitselected_one;
				mywinnerslist[counter].Winner_round_bitselected_two = mycondlist.bitselected_two;
				mywinnerslist[counter].Winner_round_bit_one_value = mycondlist.bit_one_value;
				mywinnerslist[counter].Winner_round_bit_two_value = mycondlist.bit_two_value;
				memcpy(mywinnerslist[counter].winner_HashOfPoW, mytempwinnerslist[counter].winner_HashOfPoW,32);
				memcpy(mywinnerslist[counter].winner_pk, mytempwinnerslist[counter].winner_pk,32);
				memcpy(mywinnerslist[counter].winner_proof, mytempwinnerslist[counter].winner_proof,80);
				memcpy(mywinnerslist[counter].winner_output, mytempwinnerslist[counter].winner_output,64);
		}
		printf("%" PRIu8 " Attestors are selected ...\n", numberofwinners);
	}
	if(winnertemp > numberofwinners){
		struct timespec t;	
		int64_t millitime = 0;
		uint8_t timestamp = 0;
		uint8_t res_winner_list[numberofwinners];
		int correct = 1;
		memset(res_winner_list, 0, sizeof(res_winner_list));
		winner =0;
		
		while(winner < numberofwinners){
			correct = 1;
			while(correct != 0){ 
				timestamp = 0;
				clock_gettime(CLOCK_REALTIME, &t);
				millitime = t.tv_nsec;
				srand(millitime);
				timestamp = rand() % winnertemp;
				correct = 0;
				for(int k = 0; k<numberofwinners; k++){
					if(mywinnerslist[k].res_winner_list == timestamp){
						correct++;
					}
				}
			}		
				mywinnerslist[winner].res_winner_list = timestamp;	
				mywinnerslist[winner].Winner_round_memoryselected_One = mycondlist.memoryselected_One;
				mywinnerslist[winner].Winner_round_memoryselected_Two = mycondlist.memoryselected_Two;
				mywinnerslist[winner].Winner_round_bitselected_one = mycondlist.bitselected_one;
				mywinnerslist[winner].Winner_round_bitselected_two = mycondlist.bitselected_two;
				mywinnerslist[winner].Winner_round_bit_one_value = mycondlist.bit_one_value;
				mywinnerslist[winner].Winner_round_bit_two_value = mycondlist.bit_two_value;			
				memcpy(mywinnerslist[winner].winner_HashOfPoW, mytempwinnerslist[timestamp].winner_HashOfPoW,32);
				memcpy(mywinnerslist[winner].winner_pk, mytempwinnerslist[timestamp].winner_pk,32);
				memcpy(mywinnerslist[winner].winner_proof, mytempwinnerslist[timestamp].winner_proof,80);
				memcpy(mywinnerslist[winner].winner_output, mytempwinnerslist[timestamp].winner_output,64);
				winner++;

		}
		printf("%" PRIu8 " Attestors are selected ...\n", winner);
	}
}

void Verify_List_Of_Winners(uint8_t orginal_listlen, uint8_t numberofwinners){
	uint8_t counter = 0;
	for(counter = 0; counter < orginal_listlen; counter++){
		if(mywinnerslist[counter].Winner_round_memoryselected_One != mycondlist.memoryselected_One){
			printf("Error: Condition 1\n");
		}
		if(mywinnerslist[counter].Winner_round_memoryselected_Two != mycondlist.memoryselected_Two){
			printf("Error: Condition 2\n");
		}		
		if(mywinnerslist[counter].Winner_round_bitselected_one != mycondlist.bitselected_one){
			printf("Error: Condition 3\n");
		}		
		if(mywinnerslist[counter].Winner_round_bitselected_two != mycondlist.bitselected_two){
			printf("Error: Condition 4\n");
		}
		if(mywinnerslist[counter].Winner_round_bit_one_value != mycondlist.bit_one_value){
			printf("Error: Condition 5\n");
		}
		if(mywinnerslist[counter].Winner_round_bit_two_value != mycondlist.bit_two_value){
			printf("Error: Condition 6\n");
		}				
	}
	
	
	for(counter = 0; counter < numberofwinners; counter++){
		if(memcmp(mytempwinnerslist[mywinnerslist[counter].res_winner_list].winner_pk, mywinnerslist[counter].winner_pk, 32)==0){
			if (!crypto_vrf_ietfdraft03_is_valid_key(mywinnerslist[counter].winner_pk)) {
				printf("Error: fake public key\n");
			}
		}else if(memcmp(mytempwinnerslist[mywinnerslist[counter].res_winner_list].winner_pk, mywinnerslist[counter].winner_pk, 32)!=0){
			printf("Error: fake user %" PRIu8 "\n", counter);
		}
		std::bitset<8> b1(mywinnerslist[counter].winner_output[mywinnerslist[counter].Winner_round_memoryselected_One]);
		std::bitset<8> b2(mywinnerslist[counter].winner_output[mywinnerslist[counter].Winner_round_memoryselected_Two]);
		int cond_One = 0;
		int cond_Two = 0;		
		if(b1[mywinnerslist[counter].Winner_round_bitselected_one] == mywinnerslist[counter].Winner_round_bit_one_value & b1[mywinnerslist[counter].Winner_round_bitselected_two] == mywinnerslist[counter].Winner_round_bit_two_value){cond_One = 1;}
		if(b2[mywinnerslist[counter].Winner_round_bitselected_one] == mywinnerslist[counter].Winner_round_bit_two_value & b2[mywinnerslist[counter].Winner_round_bitselected_two] == mywinnerslist[counter].Winner_round_bit_one_value){cond_Two = 1;}
		if(cond_One != 1 || cond_Two != 1){
			printf("Error: invalid member ...");
		}
		if(!crypto_vrf_ietfdraft03_verify(mywinnerslist[counter].winner_output, mywinnerslist[counter].winner_pk, mywinnerslist[counter].winner_proof,  mywinnerslist[counter].winner_HashOfPoW, sizeof(mywinnerslist[counter].winner_HashOfPoW))){
			printf("Error: invalid proof\n");
		}
	}
}

int select(uint8_t listsize, uint8_t Attestors_Required){
	
	uint32_t i = 0;
	Generate_List(listsize);
	printmembers(listsize);
	generate_condition(mycondlist.memoryselected_One, mycondlist.memoryselected_Two, mycondlist.bitselected_one, mycondlist.bitselected_two, mycondlist.bit_one_value, mycondlist.bit_two_value);
	mycondlist.round = i;
	generate_List_Of_Winners(listsize, Attestors_Required);
	printmytempwinnerslist(listsize);
	mywinnerslist[mycondlist.round].Winner_round = mycondlist.round;
	Verify_List_Of_Winners(listsize, Attestors_Required);
	printmywinnerslist(Attestors_Required);
	i++;
	generate_condition(mycondlist.memoryselected_One, mycondlist.memoryselected_Two, mycondlist.bitselected_one, mycondlist.bitselected_two, mycondlist.bit_one_value, mycondlist.bit_two_value);
	mycondlist.round = i;
	generate_List_Of_Winners(listsize, Attestors_Required);
	printmytempwinnerslist(Attestors_Required);
	mywinnerslist[mycondlist.round].Winner_round = mycondlist.round;
	Verify_List_Of_Winners(listsize, Attestors_Required);
	printmywinnerslist(Attestors_Required);
	return 0;
}