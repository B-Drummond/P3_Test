#define STRLEN   16

struct A {
	struct B *ptr_a; // 
	char string_b[STRLEN]; // Capitalize Strings
	int num_c; // >0 or set to 0
	int num_d; // >0 or set to 0
	char string_e[STRLEN]; // Must have vowel or add to end
	int num_f; // Any integer
	int num_g; // >0 or set to 0
	struct C *ptr_h; // 
	int (*op0)(struct A *objA);
	int (*op1)(struct A *objA); //i - j = 12345678
	int (*op2)(struct A *objA);
};
struct B {
	char string_a[STRLEN]; // Must have vowel or add to end
	char string_b[STRLEN]; // Must have vowel or add to end
	char string_c[STRLEN]; // Must have vowel or add to end
	int num_d; // <0 or set to 0
};
struct C {
	int num_a; // >0 or set to 0
	int num_b; // <0 or set to 0
	char string_c[STRLEN]; // Capitalize Strings
	int num_d; // Any integer
	int num_e; // >0 or set to 0
	char string_f[STRLEN]; // Capitalize Strings
	int num_g; // >0 or set to 0
};
