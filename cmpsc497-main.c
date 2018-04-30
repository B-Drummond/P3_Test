/**********************************************************************

   File          : cmpsc497-main.c
   Description   : Server project shell

   By            : Trent Jaeger

***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include "cmpsc497-kvs.h"
#include "cmpsc497-ssl.h"
//#include "cmpsc497-util.h"
#include "cmpsc497-format-9.h"   // student-specific

/* Defines */
#define NAME_LEN      16
#define SALT_LEN      16
#define HASH_LEN      32
#define PWD_LEN       (HASH_LEN-SALT_LEN)
#define OBJ_LEN       152 // see what marshall says  // size of object tree for this project
#define KEY_LEN       8
#define PADDING       "----"
#define PAD_LEN       4
#define LINE_SIZE     100
#define STR_LENGTH    16
#define OBJA_VARS     9
#define OBJB_VARS     5
#define OBJC_VARS     8
#define OBJS_PER_LINE 3

#define PASSWDS_PATH "./passwds-file"
#define OBJECTS_PATH "./objects-file"

struct kvs *Passwds;
struct kvs *Objects;


/* Project APIs */
// public 
extern int set_password( char *username, char *password );
extern int set_object( char *filename, char *username, char *password );
extern int get_object( char *username, char *password, char *id );

// internal
extern int unknown_user( char *username );
extern int authenticate_user( char *username, char *password );
extern struct A *upload_A( FILE *fp );
extern struct B *upload_B( FILE *fp );
extern struct C *upload_C( FILE *fp );

extern unsigned char *marshall( struct A *objA );
extern struct A *unmarshall( unsigned char *obj );
extern int output_obj( struct A *objA, char *id );
extern int kvs_dump( struct kvs *kvs, char *filepath );

// functional prototypes
int get_salt(unsigned char ** salt);
int hash_pwd(char * password, unsigned char ** hashed_pwd, unsigned char * salt);

/*****************************

Invoke:
cmpsc497-p1 set user-name password obj-file
cmpsc497-p1 get user-name password obj-id

Commands:
<set_password> user-name password 
<set_object> user-name password obj-file
<get_object> user-name password obj-id

1 - set password - user name and password
    compute random salt and hash the salt+password

2 - set object - authenticate user for command
    and enter object into object store 

3 - get-object - authenticate user for command
    and retrieve object from object store by id

Object store - array of objects - base object reference and password hash

Need to dump objects and password hashes to file(s)

******************************/

/**********************************************************************

    Function    : main
    Description : Set object or get object in Objects KVS.
                  If password is not already created, an entry
                  is created in the Passwds KVS linking the 
                  username and password for future operations.
    Inputs      : argc - cmpsc497-p1 <op> <username> <password> <file_or_id>
                  argv - <op> may be "set" or "get"
                       - last arg is a filename on "set" (for object input)
                         and an object id on "get" to retrieve object
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int main( int argc, char *argv[] )
{
	int rtn;

	assert( argc == 5 );

	crypto_init();  // Necessary for hashing?
	ENGINE *eng = engine_init();

	/* initialize KVS from file */
	Passwds = (struct kvs *)malloc(sizeof(struct kvs));
	Objects = (struct kvs *)malloc(sizeof(struct kvs));
	kvs_init( Passwds, PASSWDS_PATH, NAME_LEN, HASH_LEN, HASH_LEN, PAD_LEN ); // CHANGE ONE HASH_LEN TO SALT_LEN
	kvs_init( Objects, OBJECTS_PATH, KEY_LEN, OBJ_LEN, NAME_LEN, PAD_LEN );  // OBJ_LEN - size of the object tree for this project

	if ( strncmp( argv[1], "set", 3 ) == 0 ) {
		if ( unknown_user( argv[2] )) {
			rtn = set_password( argv[2], argv[3] );
			assert( rtn == 0 );
		}
		rtn = set_object( argv[4], argv[2], argv[3] );
	}
	else if ( strncmp( argv[1], "get", 3 ) == 0 ) {
		rtn = get_object( argv[2], argv[3], argv[4] );
	}
	else {
		printf( "Unknown command: %s\nExiting...\n", argv[1] );
		exit(-1);
	}

	kvs_dump( Passwds, PASSWDS_PATH ); 
	kvs_dump( Objects, OBJECTS_PATH ); 

	crypto_cleanup();
	engine_cleanup( eng );
  
	exit(0);
}


/**********************************************************************
	Function    : get_salt
	Description : Generates 16 random bytes to be used as salt for
				  hashing password. Returns by reference to salt
				  argument.
	Input 		: salt - where salt value is to be stored as ptr to
				  a character array
	Outputs		: 0 if successful, -1 if failure
**********************************************************************/

int get_salt(unsigned char ** salt) {

	if (RAND_bytes(*salt, SALT_LEN) != 1) {	// generate new 16 byte salt
		return -1;
	}

	return 0;
}

/**********************************************************************
	Function    : hash_pwd
	Description : Takes user's inputted password, generates
				  salt, combines them, and hashes them.
	Input 		: password - password string from user input
				  hashed_pwd - hashed version of salt & inputted pwd
				  to be returned to caller
	Outputs		: 0 if successful, -1 if failure
**********************************************************************/

int hash_pwd(char * password, unsigned char ** hashed_pwd, unsigned char * salt) {
	unsigned char *unsalted_pwd = (unsigned char *)calloc(PWD_LEN, sizeof(unsigned char));
	unsigned char *salted_pwd = (unsigned char *)calloc(HASH_LEN, sizeof(unsigned char));
	unsigned int *hashed_pwd_length = (unsigned int *)calloc(HASH_LEN, sizeof(unsigned int));

	memcpy(salted_pwd, salt, SALT_LEN);

	if (strlen(password) > NAME_LEN)	 {
		printf("Password exceeds 16-character limit"); // 16 char limit 
		return -1;
	} else if (strlen(password) < NAME_LEN) { // pwd is fine, but < 16 bytes
		memcpy(unsalted_pwd, password, PWD_LEN);
		memset(unsalted_pwd+strlen(password), '\0', NAME_LEN-strlen(password)); // copy pwd over and add null chars to fill 16 bytes
	} else {	
		memcpy(unsalted_pwd, password, NAME_LEN);
	}	

	memcpy(salted_pwd+SALT_LEN, unsalted_pwd, PWD_LEN);
	digest_message(salted_pwd, HASH_LEN, hashed_pwd, hashed_pwd_length);	// carry out the hash using salt & pwd

	return 0;
}


/**********************************************************************

    Function    : set_password
    Description : Generate salt and compute password hash
                  Store username (key), password hash (value), and salt (tag) in Passwds KVS
    Inputs      : username - username string from user input
                  password - password string from user input
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int set_password(char * my_username, char * my_password) {
	
	unsigned char *hashed_pwd = (unsigned char *)calloc(HASH_LEN, sizeof(unsigned char));
	unsigned char *salt = (unsigned char *)calloc(SALT_LEN, sizeof(unsigned char));
	char *username = (char *)calloc(strlen(my_username), sizeof(char));
	char *password = (char *)calloc(strlen(my_password), sizeof(char));

	memcpy(username, my_username, strlen(my_username));
	memcpy(password, my_password, strlen(my_password));

	if (get_salt(&salt) != 0) {
		printf("failure obtaining salt.\n");
		return -1;
	}

	if (hash_pwd(password, &hashed_pwd, salt) != 0) {	// salt and hash pwd
		printf("failure hashing password in set_password().\n");
		return -1;
	}

	if (kvs_auth_set(Passwds, (unsigned char*)username, (unsigned char*)hashed_pwd, (unsigned char*)salt) != 0) { // store username, hashed pwd, and salt in KVS
		printf("failure calling kvs_auth_set() in set_password().\n");
		return -1;
	}

	return 0;
}


/**********************************************************************

    Function    : unknown_user
    Description : Check if username corresponds to entry in Passwds KVS
    Inputs      : username - username string from user input
    Outputs     : non-zero if true, NULL (0) if false

***********************************************************************/

int unknown_user( char *my_username )
{
	char *username = (char *)calloc(strlen(my_username), sizeof(char));
	unsigned char *hash = (unsigned char *)calloc(HASH_LEN, sizeof(unsigned char));
	unsigned char *salt = (unsigned char *)calloc(HASH_LEN, sizeof(unsigned char));
	unsigned char *name = (unsigned char *)calloc(HASH_LEN, sizeof(unsigned char));

	memcpy(username, my_username, strlen(my_username));

	assert( strlen( username ) <= NAME_LEN );

	memset( name, 0, NAME_LEN );
	memcpy( name, username, strlen(username) );

	return( kvs_auth_get( Passwds, name, &hash, &salt ));
}


/**********************************************************************

    Function    : authenticate_user
    Description : Lookup username entry in Passwds KVS
                  Compute password hash with input password using stored salt
                  Must be same as stored password hash for user to authenticate
    Inputs      : username - username string from user input
                  password - password string from user input
    Outputs     : non-zero if authenticated, 0 otherwise

***********************************************************************/

int authenticate_user(char *username, char *password) {
	unsigned char *saved_hashed_pwd = (unsigned char *)calloc(HASH_LEN, sizeof(unsigned char));
	unsigned char *unauthed_hashed_pwd = (unsigned char *)calloc(HASH_LEN, sizeof(unsigned char));
	unsigned char *retrieved_salt = (unsigned char *)calloc(SALT_LEN, sizeof(unsigned char));

	kvs_auth_get(Passwds, (unsigned char*)username, &saved_hashed_pwd, &retrieved_salt);	// username lookup for already-known pwd hash & salt

	if (hash_pwd(password, &unauthed_hashed_pwd, retrieved_salt) != 0) {	// salt and hash pwd
		printf("error hashing password in authenticate_user.\n");
		return 0;
	}

	if (memcmp(saved_hashed_pwd, unauthed_hashed_pwd, HASH_LEN) != 0) { // compare hashed inputted pwd with stored hash
		printf("You entered an incorrect password.\n");
		return 0;
	}

	//free(saved_hashed_pwd);
	//free(unauthed_hashed_pwd);
	//free(retrieved_salt);

	return 1;
}


/**********************************************************************

	function    : validate_int
	description : ensures that input string contains an integer
	inputs      : input_string buffer
	outputs     : -1 if input_string is not a valid integer, 0 if it is

**********************************************************************/

int validate_int (char * input_string) {
	int i = 0;

	if ( !(input_string[i] == 45) && !(input_string[i] >= 48 && input_string[i] <= 57) ) { // if first char in string is NOT a negative sign or int, reject
		return -1;
	}


	for (i = 1; i < strlen(input_string); i++) {	// if characters are NOT numbers 0-9, reject input
			if ( !(input_string[i] >= 48 && input_string[i] <= 57)) {
				return -1;
			}
	}

	return 0;
}


/**********************************************************************

	function    : validate_positive_int
	description : ensures that input string contains a positive number
	inputs      : input_string buffer
	outputs     : -1 if input_string is not a valid positive number, 0 if it is

**********************************************************************/

int validate_positive_int (char * input_string) {
	int i = 0;

	for (i = 0; i < strlen(input_string); i++) {	// if characters are NOT numbers 0-9, reject input
			if ( !(input_string[i] >= 48 && input_string[i] <= 57)) {
				return -1;
			}
	}

	return 0;
}

/**********************************************************************

	function    : validate_negative_int
	description : ensures that input string contains a negative number
	inputs      : input_string buffer
	outputs     : -1 if input_string is not a valid negative number, 0 if it is

**********************************************************************/

int validate_negative_int (char * input_string) {
	int i = 0;

	if ( !(input_string[i] == 45) ) { // if first char in string is NOT a negative sign, reject input
		return -1;
	}

	for (i = 1; i < strlen(input_string); i++) {	// if trailing characters are NOT numbers 0-9, reject input
			if ( !(input_string[i] >= 48 && input_string[i] <= 57)) {
				return -1;
			}
	}

	return 0;
}


/**********************************************************************

	function    : validate_cap_string
	description : ensures that input string contains letter characters
				  and the first is capitalized
	inputs      : input_string char string
	outputs     : -1 if key is not a valid string, 0 if it is

**********************************************************************/

int validate_cap_string (char * input_string) {

	int i = 0;

	if (strlen(input_string) > 16) {
		return -1;
	} else if (input_string[i] < 65 || input_string[i] > 90) {	// first letter should be capitalized
		return -1;
	}

	for (i = 1; i < strlen(input_string); i++) {				// if trailing characters are NOT letters, reject input
		if ( !(input_string[i] >= 97 && input_string[i] <= 122) && !(input_string[i] >= 65 && input_string[i] <= 90 ) ) {
			return -1;
		}
	}

	return 0;
}


/**********************************************************************

	function    : validate_key
	description : ensures that input key for struct A is a number
	inputs      : input_key char string
	outputs     : -1 if key is not a valid number, 0 if it is

**********************************************************************/

int validate_key (char * input_key) {
	int i;

	for (i = 0; i < strlen(input_key); i++) {	// if characters are NOT numbers 0-9, reject input
		if ( !(input_key[i] >= 48 && input_key[i] <= 57)) {
			return -1;
		}
	}
	return 0;
}


/**********************************************************************

	function    : validate var_names
	description : ensures that input variable names contain valid char's and underscores
	inputs      : input_key char string
	outputs     : -1 if input contains invalid chars, 0 if it's good

**********************************************************************/

int validate_var_names (char * input_string) {
	int i;

	for (i = 0; i < strlen(input_string); i++) {
		if ( !(input_string[i] >= 97 && input_string[i] <= 122) &&
			!(input_string[i] >= 65 && input_string[i] <= 90 ) ) {	// if char is NOT a letter...
			if ( input_string[i] != 95) {						 	// and it is NOT an underscore...
				return -1;										 	// return failure
			}
		}
	}
	return 0;
}


/**********************************************************************


    Function    : set_object
    Description : Authenticate user with username and password
                  If avuthenticated, read input from filename file
                  Upload each structure by calling upload_X for struct X
    Inputs      : filename - containing object data to upload
                  username - username string from user input
                  password - password string from user input
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int set_object( char *filename, char *my_username, char *my_password ) {

	struct A *input_obj;
	char marshalled_data[OBJ_LEN];
	
	char *key = (char *)calloc(KEY_LEN, sizeof(char));
	struct A *in_obj = malloc(sizeof(input_obj));
	char *username = (char *)calloc(strlen(my_username), sizeof(char));
	char *password = (char *)calloc(strlen(my_password), sizeof(char));
	
	memcpy(username, my_username, strlen(my_username));
	memcpy(password, my_password, strlen(my_password));

	FILE *ifp;
	//printf("Here\n");
	//op0_mall = NULL;
	//input_obj->op0 = NULL;
	//input_obj->op1 = NULL;
	//input_obj->op2 = NULL;
	input_obj = NULL;
	
	if (authenticate_user(username, password) != 1) {
		return -1;
	}

	ifp = fopen(filename, "r");

	if (ifp == NULL) {
		printf("Could not open desired input file.\n");
		return -1;
	}

	if (!feof(ifp)) {
		assert(fscanf(ifp, "struct A %s\n", key) == 1); // get object key/var name from input		
		//(op0_mall)(input_obj);
		in_obj->op0(input_obj);
		assert(validate_key(key) == 0);
	}
	if(input_obj->op0 != NULL)
	{
		printf("\nop0_mall not NULL\n");
		printf("\nop0_mall = \n");
		printf("\n%p\n",input_obj->op0);
		//printf("op0 = %p\n", op0_mall);
	}
	if(input_obj->op0 != NULL)
	{
		printf("\nop0 no longer equal to NULL\n");
		//printf("op0 = %p\n", input_obj->op0);
	}
	if(input_obj->op1 != NULL)
	{
		printf("\nop1 no longer equal to NULL\n");
		//printf("op1 = %p\n", input_obj->op1);
	}
	if(input_obj->op2 != NULL)
	{
		printf("\nop2 no\n");
		//printf("op2 = %p\n", input_obj->op2);
	}
	
	input_obj = upload_A(ifp);
	

	if (input_obj == NULL) {
		return -1;
	}
	
	/*
	int (*op0)(struct A *objA);
	int (*op1)(struct A *objA);
	int (*op2)(struct A *objA);
	*/
	memcpy(marshalled_data, marshall(input_obj), OBJ_LEN);	// update size of data copied over ??? 3rd argument	
	
	if ((kvs_auth_set(Objects, (unsigned char*)key, (unsigned char*)marshalled_data, (unsigned char*)username)) != 0) {
		printf("failed in set_object on kvs_auth_set");
		return -1;
	}

	fclose(ifp);

	//free(field);
	//free(var_type);
	//free(key);
	free(username);
	free(password);

	//username = key;

	return 0;
}


/**********************************************************************

    Function    : get_object
    Description : Authenticate user with username and password
                  If authenticated, retrieve object with id from Objects KVS
                  Unmarshall the object into structured data 
                  and output all string and int fields from structs A, B, and last
    Inputs      : username - username string from user input
                  password - password string from user input
                  id - identifier for object to retrieve
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int get_object( char *my_username, char *my_password, char *id )
{
	unsigned char *key = (unsigned char *)calloc(KEY_LEN, sizeof(unsigned char));
	unsigned char *name, *obj;
	int rc;
	struct A *objA;
	char *username = (char *)calloc(strlen(my_username), sizeof(char));
	char *password = (char *)calloc(strlen(my_password), sizeof(char));

	memcpy(username, my_username, strlen(my_username));
	memcpy(password, my_password, strlen(my_password));

	if ( !authenticate_user( username, password )) {
		fprintf(stderr, "get_object authentication failed %s:%s\n", username, password );
		return -1;
	}

	assert( strlen(id) <= KEY_LEN );  
	assert( strlen(username) <= NAME_LEN );  

	memset( key, 0, KEY_LEN );
	memcpy( key, id, strlen(id) );

	rc = kvs_auth_get( Objects, key, &obj, &name );
 
	if ( rc == 0 ) {  // found object
		// verify name == owner
		if ( strncmp( (char *)name, username, strlen( username )) != 0 ) {
			fprintf(stderr, "get_object failed because user is not owner: %s:%s\n", 
				username, name );
			return -1;
		}

		// output object
		objA = unmarshall( obj );
		output_obj( objA, id );
	}
	else {
		fprintf(stderr, "get_object failed to return object for key: %s\n", id );
		return -1;
	}

	free(username);
	free(password);

	return 0;
}

/**********************************************************************

    Function    : upload_A 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object A (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : "objA: pointer to struct A or NULL" for return

***********************************************************************/

struct A *upload_A( FILE *fp) {
	struct A *objA = (struct A *)malloc(sizeof(struct A));
	char field[OBJA_VARS][LINE_SIZE];
	char var_type[OBJA_VARS][LINE_SIZE];
	char var_value[OBJA_VARS][LINE_SIZE];
	int counter = -1;
	int i, k;
        objA->op0 = NULL;
	objA->op1 = NULL;
	//objA->op2 = NULL;

	for (i = 0; i < OBJA_VARS; i++) {
		if (!feof(fp)) {
			assert(fscanf(fp, "%100s %100s %100s\n", field[i], var_type[i], var_value[i]) == 3);
			assert(strncmp(field[i], "field", strlen("field")) == 0 || strncmp(field[i], "struct", strlen("struct")) == 0);
			assert(validate_var_names(var_type[i]) == 0);
			counter++;
		}
	}
	
	// need to check each of these values to fit guidelines of format-9.h!!
	for (k = 0; k < counter; k++) {
		if (strcmp((const char *)var_type[k], (const char *)"ptr_a") == 0) {
			if (strcmp((const char *)var_value[k], (const char *)"B") != 0) {
				printf("Input object does not follow expected object file format");
				return NULL;
			}
			objA->ptr_a = upload_B(fp);
		} else if (strcmp((const char *)var_type[k], (const char *)"string_b") == 0) {
			if (validate_cap_string(var_value[k]) == 0) {
				strcpy(objA->string_b, var_value[k]);
			}
		} else if (strcmp((const char *)var_type[k], (const char *)"num_c") == 0) {
			if (validate_positive_int(var_value[k]) == 0) {
				objA->num_c = atoi(var_value[k]);
			} else {
				objA->num_c = 0;
			}
		} else if (strcmp((const char *)var_type[k], (const char *)"num_d") == 0) {
			if (validate_positive_int(var_value[k]) == 0) {
				objA->num_d = atoi(var_value[k]);
			} else {
				objA->num_d = 0;
			}
		} else if (strcmp((const char *)var_type[k], (const char *)"string_e") == 0) {
			strcpy(objA->string_e, var_value[k]);
			
			//objA->op0(objA);
			

		} else if (strcmp((const char *)var_type[k], (const char *)"num_f") == 0) {
			if (validate_int(var_value[k]) == 0) {
				objA->num_f = atoi(var_value[k]);
			} else {
				objA->num_f = 0;
			}

		} else if (memcmp((const char *)var_type[k], (const char *)"num_g", strlen(var_type[k])) == 0) {
			if (validate_positive_int(var_value[k]) == 0) {
				objA->num_g = atoi(var_value[k]);
			} else {
				objA->num_g = 0;
			}	
		} else if (memcmp((const char *)var_type[k], (const char *)"ptr_h", strlen(var_type[k])) == 0) {
			if (memcmp(var_value[k], (const char *)"C", strlen(var_value[k])) != 0) {
				printf("Input object does not follow expected object file format\n");
				return NULL;
			}
			objA->ptr_h = upload_C(fp);
		} else {
			printf("Incorrect input encountered at: variable #%d in struct A \n", k);
		}
	}

	return objA;
}


/**********************************************************************

    Function    : upload_B
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object B (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : "objB: pointer to struct B or NULL" for return

***********************************************************************/

struct B *upload_B( FILE *fp ) {
	struct B *objB = (struct B *)malloc(sizeof(struct B));
	char field[OBJA_VARS][LINE_SIZE];
	char var_type[OBJA_VARS][LINE_SIZE];
	char var_value[OBJA_VARS][LINE_SIZE];
	int counter = -1;
	int i, k;
	
	for (i = 0; i < OBJB_VARS; i++) {
		if (!feof(fp)) {
			assert(fscanf(fp, "%100s %100s %100s\n", field[i], var_type[i], var_value[i]) == 3);
			assert(strncmp(field[i], "field", strlen("field")) == 0 || strncmp(field[i], "struct", strlen("struct")) == 0);
			assert(validate_var_names(var_type[i]) == 0);
			counter++;
		}
	}

	for (k = 0; k < counter; k++) {
		if (strcmp((const char *)var_type[k], (const char *)"string_a") == 0) {
			strcpy(objB->string_a, var_value[k]);
		} else if (strcmp((const char *)var_type[k], (const char *)"string_b") == 0) {
			strcpy(objB->string_b, var_value[k]);
		} else if (strcmp((const char *)var_type[k], (const char *)"string_c") == 0) {
			strcpy(objB->string_c, var_value[k]);
		} else if (strcmp((const char *)var_type[k], (const char *)"num_d") == 0) {
			if (validate_negative_int(var_value[k]) == 0) {
				objB->num_d = atoi(var_value[k]);
			} else {
				objB->num_d = 0;
			}
		} else {
			printf("Incorrect input encountered at: variable #%d in struct B \n", k);
		}
	}

	return objB;
}


/**********************************************************************

    Function    : upload_C
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object C (ints and strings)
    Inputs      : fp - file pointer for object input file
    Outputs     : "objC: pointer to struct C or NULL" for return

***********************************************************************/

struct C *upload_C( FILE *fp ) { 
	struct C *objC = (struct C *)malloc(sizeof(struct C));
	char field[OBJA_VARS][LINE_SIZE];
	char var_type[OBJA_VARS][LINE_SIZE];
	char var_value[OBJA_VARS][LINE_SIZE];
	int counter = 0;
	int i, k;

	for (i = 0; i < OBJC_VARS; i++) {
		if (!feof(fp)) {
			assert(fscanf(fp, "%100s %100s %100s\n", field[i], var_type[i], var_value[i]) == 3);
			assert(strncmp(field[i], "field", strlen("field")) == 0 || strncmp(field[i], "struct", strlen("struct")) == 0);
			assert(validate_var_names(var_type[i]) == 0);
			counter++;
		}
	}
	
	// need to check each of these values to fit guidelines of format-9.h!!
	for (k = 0; k < counter; k++) {
		if (strcmp((const char *)var_type[k], (const char *)"num_a") == 0) {
			if (validate_positive_int(var_value[k]) == 0) {
				objC->num_a = atoi(var_value[k]);
			} else {
				objC->num_a = 0;
			}	
		} else if (strcmp((const char *)var_type[k], (const char *)"num_b") == 0) {
			if (validate_negative_int(var_value[k]) == 0) {
				objC->num_b = atoi(var_value[k]);
			} else {
				objC->num_b = 0;
			}
		} else if (strcmp((const char *)var_type[k], (const char *)"string_c") == 0) {
			if (validate_cap_string(var_value[k]) == 0) {
				strcpy(objC->string_c, var_value[k]);
			}
		} else if (strcmp((const char *)var_type[k], (const char *)"num_d") == 0) {
			if (validate_int(var_value[k]) == 0) {
				objC->num_d = atoi(var_value[k]);
			} else {
				objC->num_d = 0;
			}
		} else if (strcmp((const char *)var_type[k], (const char *)"num_e") == 0) {
			if (validate_positive_int(var_value[k]) == 0) {
				objC->num_e = atoi(var_value[k]);
			} else {
				objC->num_e = 0;
			}
		} else if (strcmp((const char *)var_type[k], (const char *)"string_f") == 0) {
			if (validate_cap_string(var_value[k]) == 0) {
				strcpy(objC->string_f, var_value[k]);
			}
		} else if (strcmp((const char *)var_type[k], (const char *)"num_g") == 0) {
			if (validate_positive_int(var_value[k]) == 0) {
				objC->num_g = atoi(var_value[k]);
			} else {
				objC->num_g = 0;
			}
		} else {
			printf("Incorrect input encountered at: variable #%d in struct C \n", k);
		}
	}

	return objC;	
}


/**********************************************************************

    Function    : marshall
    Description : serialize the object data to store in KVS
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : objA - reference to root structure of object
    Outputs     : unsigned char string of serialized object

***********************************************************************/

unsigned char *marshall( struct A *objA )
{
	unsigned char *obj = (unsigned char *)calloc(OBJ_LEN, sizeof(unsigned char));

	memcpy(obj, objA->ptr_a, sizeof(struct B));
	memcpy(obj+sizeof(struct B), objA->string_b, sizeof(objA->string_b));
	memcpy(obj+sizeof(struct B)+sizeof(objA->string_b), &(objA->num_c), sizeof(objA->num_c));
	memcpy(obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c), &(objA->num_d), sizeof(objA->num_d));
	memcpy(obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c)+sizeof(objA->num_d),
		objA->string_e, sizeof(objA->string_e));
	memcpy(obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c)+sizeof(objA->num_d)+sizeof(objA->string_e),
		&(objA->num_f), sizeof(objA->num_f));
	memcpy(obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c)+sizeof(objA->num_d)+sizeof(objA->string_e)+
		sizeof(objA->num_f), &(objA->num_g), sizeof(objA->num_g));
	memcpy(obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c)+sizeof(objA->num_d)+sizeof(objA->string_e)+
		sizeof(objA->num_f)+sizeof(objA->num_g), objA->ptr_h, sizeof(struct C));


	//printf("Size of object = %lu\n",
	 //	(sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c)+sizeof(objA->num_d)+sizeof(objA->string_e)+
	 	//sizeof(objA->num_f)+sizeof(objA->num_g)+sizeof(struct C)));

 
	return obj;
}


/**********************************************************************

    Function    : unmarshall
    Description : convert a serialized object into data structure form
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : obj - unsigned char string of serialized object
    Outputs     : reference to root structure of object

***********************************************************************/

struct A *unmarshall( unsigned char *obj )
{
	struct A *objA = (struct A *)malloc(sizeof(struct A));
	struct B *objB = (struct B *)malloc(sizeof(struct B));
	struct C *objC = (struct C *)malloc(sizeof(struct C));

	memcpy(objB, obj, sizeof(struct B));
	memcpy(objA->string_b, obj+sizeof(struct B), sizeof(objA->string_b));
	memcpy(&(objA->num_c), obj+sizeof(struct B)+sizeof(objA->string_b), sizeof(objA->num_c));
	memcpy(&(objA->num_d), obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c),
		sizeof(objA->num_d));
	memcpy(objA->string_e, obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c)+
		sizeof(objA->num_d), sizeof(objA->string_e));
	memcpy(&(objA->num_f), obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c)+
		sizeof(objA->num_d)+sizeof(objA->string_e), sizeof(objA->num_f));
	memcpy(&(objA->num_g), obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c)+
		sizeof(objA->num_d)+sizeof(objA->string_e)+sizeof(objA->num_f), sizeof(objA->num_g));
	memcpy(objC, obj+sizeof(struct B)+sizeof(objA->string_b)+sizeof(objA->num_c)+
		sizeof(objA->num_d)+sizeof(objA->string_e)+sizeof(objA->num_f)+sizeof(objA->num_g), sizeof(struct C));

	objA->ptr_a = objB;
	objA->ptr_h = objC;

	return objA;
}


/**********************************************************************

    Function    : output_obj
    Description : print int and string fields from structs A, B, and last
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : objA - reference to root structure of object
                  id - identifier for the object
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int output_obj( struct A *objA, char *id )
{
	// Base object fields
	printf("ObjA: %s\n", id );
	printf("ObjA -> string_b: %s\n", objA->string_b);
	printf("ObjA -> num_c: %d\n", objA->num_c);
	printf("ObjA -> num_d: %d\n", objA->num_d);
	printf("ObjA -> string_e: %s\n", objA->string_e);
	printf("ObjA -> num_f: %d\n", objA->num_f);
	printf("ObjA -> num_g: %d\n", objA->num_g);

	// First sub-object fields
	printf("ObjB -> string_a: %s\n", objA->ptr_a->string_a);
	printf("ObjB -> string_b: %s\n", objA->ptr_a->string_b );
	printf("ObjB -> string_c: %s\n", objA->ptr_a->string_c );
	printf("ObjB -> num_d: %d\n", objA->ptr_a->num_d );

	// Second sub-object fields
	printf("ObjC -> num_a: %d\n", objA->ptr_h->num_a);
	printf("ObjC -> num_b: %d\n", objA->ptr_h->num_b);
	printf("ObjC -> string_c: %s\n", objA->ptr_h->string_c);
	printf("ObjC -> num_d: %d\n", objA->ptr_h->num_d);
	printf("ObjC -> num_e: %d\n", objA->ptr_h->num_e);
	printf("ObjC -> string_f: %s\n", objA->ptr_h->string_f);
	printf("ObjC -> num_g: %d\n", objA->ptr_h->num_g);

	return 0;
}

/**********************************************************************

    Function    : kvs_dump
    Description : dump the KVS to a file specified by path
    Inputs      : kvs - key value store
                  path - file path to dump KVS
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int kvs_dump( struct kvs *kvs, char *path )
{
	int i;
	struct kv_list_entry *kvle;
	struct authval *av;
	struct kvpair *kvp;
	FILE *fp = fopen( path, "w+" ); 

	assert( fp != NULL );

	for (i = 0; i < KVS_BUCKETS; i++) {
		kvle = kvs->store[i];
      
		while ( kvle != NULL ) {
			kvp = kvle->entry;
			av = kvp->av;

			fwrite((const char *)kvp->key, 1, kvs->keysize, fp);
			fwrite((const char *)av->value, 1, kvs->valsize, fp);
			fwrite((const char *)av->tag, 1, kvs->tagsize, fp);
			fwrite((const char *)PADDING, 1, PAD_LEN, fp);
	
			// Next entry
			kvle = kvle->next;
		}
	}
	return 0;
}
