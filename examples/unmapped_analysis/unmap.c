/**
* Author: David Manouchehri
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

int block_size = 40; /* Hex SHA1 representation. */

char **keys = (char *[]){
	"87ceced7dbc4a4f1557edf87be4a0853807f6b5d",
	"e6dba991c1745128787fbc7a9843306cb2bcc63e",
	"0db3aa9c620208a1a35bea318e99c678e81d0e7e",
	"275edf0657388c3a1197cdadfad7b96da0f977a3",
	"1d8b18780e2c154ca110131638d44b469a40b273",
	"900cc11181d78f3d1a5c655f5f9ff16d9872b3af",
	"1bc7763e91fb2d8bcebdabf50c298faa90a0af4b",
	"6297a22b64a46865043de4a641d4799108064396",
	"f86c47f81238e1c7894b60a0901c5eada711fb0d"
};

int valid() {
	printf("Memory is all good.\n");
	exit(EXIT_SUCCESS);
}

int invalid() {
	printf("Hey, how'd you get here?\n");
	exit(EXIT_FAILURE);
}

int breaker(char *input) {
	char valid_read[block_size], invalid_read[block_size], valid_write[block_size], invalid_write[block_size];
	strncpy(valid_read, keys[0], block_size);
	strncpy(invalid_read, keys[1], block_size);
	strncpy(valid_write, keys[2], block_size);
	strncpy(invalid_write, keys[3], block_size);

	if(strncmp(input, valid_read, block_size) == 0) {
		volatile int dont_opt_out = strncmp(keys[4], keys[5], block_size);
		valid();
	} else if(strncmp(input, invalid_read, block_size) == 0) {
		for(void *i = (void *) 0x1337; ; i += block_size) {
			printf("Reading from %p\n", i);
			volatile int dont_opt_out = strncmp(i, keys[6], block_size);
		}
		invalid();
	} else if(strncmp(input, valid_write, block_size) == 0) {
		volatile char *dont_opt_out = strncpy(valid_write, keys[7], block_size);
		valid();
	} else if(strncmp(input, invalid_write, block_size) == 0) {
		for(void *i = (void *) 0x44444444; ; i += block_size) {
			printf("Writing to %p...\n", i);
			volatile char *dont_opt_out = strncpy(i, keys[8], block_size);
		}
		invalid();
	}
	return 0;
}

int main(int argc, char **argv) {
	char input[block_size + 1];
	int state;

	printf("Input:\n");
	read(0, input, block_size);

	state = breaker(input);

	if (!state) {
		printf("You're not even trying.\n");
		exit(EXIT_FAILURE);
	}
	else {
		printf("That's odd.\n");
		exit(1337);
	}
}
