#include<stdbool.h>
#include<stdio.h>
#include<string.h>
#define w 32
#define r 20    
#define mybytes   (w / 8)
#define c       ((b + mybytes - 1) / mybytes)
#define myR24     (2 * r + 4)
#define mylgw     5
unsigned int mS[myR24 - 1];
#define mP32 0xB7E15163
#define mQ32 0x9E3779B9
#define myROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define myROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
void myRc6KeySetup(unsigned char *K, int b)
{
	int i, j, s, v;
	unsigned int L[(32 + mybytes - 1) / mybytes];
	unsigned int A, B;
	L[c - 1] = 0;
	for (i = b - 1; i >= 0; i--)
		L[i / mybytes] = (L[i / mybytes] << 8) + K[i];
	mS[0] = mP32;
	for (i = 1; i <= 2 * r + 3; i++)
		mS[i] = mS[i - 1] + mQ32;
	A = B = i = j = 0;
	v = myR24;
	if (c > v) v = c;
	v *= 3;
	for (s = 1; s <= v; s++)
	{
		A = mS[i] = myROTL(mS[i] + A + B, 3);
		B = L[j] = myROTL(L[j] + A + B, A + B);
		i = (i + 1) % myR24;
		j = (j + 1) % c;
	}
}
void myRc6BlockEncrypt(unsigned int *pt, unsigned int *ct)
{
	unsigned int A, B, C, D, t, u, x;
	int i, j;
	A = pt[0];
	B = pt[1];
	C = pt[2];
	D = pt[3];
	B += mS[0];
	D += mS[1];
	for (i = 2; i <= 2 * r; i += 2)
	{
		t = myROTL(B * (2 * B + 1), mylgw);
		u = myROTL(D * (2 * D + 1), mylgw);
		A = myROTL(A ^ t, u) + mS[i];
		C = myROTL(C ^ u, t) + mS[i + 1];
		x = A;
		A = B;
		B = C;
		C = D;
		D = x;
	}
	A += mS[2 * r + 2];
	C += mS[2 * r + 3];
	ct[0] = A;
	ct[1] = B;
	ct[2] = C;
	ct[3] = D;
}
void myRc6BlockDecrypt(unsigned int *ct, unsigned int *pt)
{
	unsigned int A, B, C, D, t, u, x;
	int i, j;
	A = ct[0];
	B = ct[1];
	C = ct[2];
	D = ct[3];
	C -= mS[2 * r + 3];
	A -= mS[2 * r + 2];
	for (i = 2 * r; i >= 2; i -= 2)
	{
		x = D;
		D = C;
		C = B;
		B = A;
		A = x;
		u = myROTL(D * (2 * D + 1), mylgw);
		t = myROTL(B * (2 * B + 1), mylgw);
		C = myROTR(C - mS[i + 1], t) ^ u;
		A = myROTR(A - mS[i], u) ^ t;
	}
	D -= mS[1];
	B -= mS[0];
	pt[0] = A;
	pt[1] = B;
	pt[2] = C;
	pt[3] = D;
}
void myprint(unsigned int n, bool end, FILE * file){
	//write data
	unsigned char *p = (unsigned char*)&n;
	int i ;
	unsigned char key[32];
	int keylen = 16;
	for (i = 0; i<4; i++){
		if (end&&i == 3){
			fprintf(file,"%02x\n", (unsigned int)(*(p + i)));
		}
		else{
			fprintf(file,"%02x ", (unsigned int)(*(p + i)));
		}
	}
}
int  main(int argc, char*argv[])
{
	unsigned int ct[4], enct[4],dect[4];
	unsigned int input_data[16];
	unsigned char key[32];
	int i;
	int keylen = 16;
	FILE * file = NULL;
	bool first_line = true;
	char mode[20];
	int which_way;//0 encryption 1 decryption
	unsigned char temp1=0,temp2=0;
	if (argc != 3){
		printf("format:./run ./input.txt ./output.txt\n");
		return 0;
	}
	file = fopen(argv[1], "r");
	if (file == NULL){
		printf("can not open %s\n",argv[1]);
		return 0;
	}
	while (!feof(file))
	{//read data
		if (first_line){
			first_line = false;
			fscanf(file, "%s\n", mode);
			if (strcmp(mode, "Encryption") == 0){
				which_way = 0;
				printf("Encryption\n");
			}
			else{
				which_way = 1;
				printf("Decryption\n");
			}
		}
		else{
			fscanf(file, "%s %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
				mode, &input_data[0],&input_data[1], &input_data[2], &input_data[3], &input_data[4], &input_data[5], &input_data[6], &input_data[7],
				&input_data[8], &input_data[9], &input_data[10], &input_data[11], &input_data[12], &input_data[13], &input_data[14], &input_data[15]);
			for (i = 0; i < 4; i++){
				ct[i] = input_data[i * 4 + 0] + (input_data[i * 4 + 1] << 8) + (input_data[i * 4 + 2] << 16) + (input_data[i * 4 + 3] << 24);
			}
			fscanf(file, "%s:", mode);
			keylen = 0;
			while(!feof(file)){
				fscanf(file, "%c", &temp1);
				//printf("%c\n", temp1);
				if ((temp1 >= '0'&&temp1 <= '9') || (temp1 >= 'a'&&temp1 <= 'f')){
					fscanf(file, "%c", &temp2);
					if (temp1 >= '0'&&temp1 <= '9'){
						temp1 = temp1 - '0';
					}
					else{
						temp1 = temp1 - 'a'+10;
					}
					if (temp2 >= '0'&&temp2 <= '9'){
						temp2 = temp2 - '0';
					}
					else{
						temp2 = temp2 - 'a' + 10;
					}
					key[keylen] = temp1 * 16 + temp2;
					keylen++;
				}
			}
			break;	
		}
	}
	fclose(file);
	file = fopen(argv[2], "w");
	if (file == NULL){
		printf("can not open %s\n", argv[2]);
		return 0;
	}
	if (which_way == 0){//which_way = 0: encryption
		//write data
		fprintf(file, "ciphertext: ");
		myRc6KeySetup(key, keylen);
		myRc6BlockEncrypt(ct, enct);
		myprint(enct[0], false,file);
		myprint(enct[1], false, file);
		myprint(enct[2], false, file);
		myprint(enct[3], true, file);
	}
	else{ // which_way = 1 : decryption
		//write data
		fprintf(file, "plaintext: ");
		myRc6KeySetup(key, keylen);
		myRc6BlockDecrypt(ct, dect);
		myprint(dect[0], false, file);
		myprint(dect[1], false, file);
		myprint(dect[2], false, file);
		myprint(dect[3], true, file);
	}
return 0;
}
