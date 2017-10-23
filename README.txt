He Hao hhao1@binghamton.edu
My code was tested on bingsuns
The way of using : 1.make  2. ./run ./input.txt ./output.txt
algorithm:
	RC6 is parameterized for w-bit words, b bytes of key, and
r rounds. The AES version of RC6 specifies b=16, 24, or 32;now,w=32; and r=20.
RC6 works with four w-bit registers A;B;C;D which contain the initial input plaintext as well as the output ciphertext at the end of encryption. The first byte of plaintext or ciphertext is placed in the least-significant byte of A; the last byte of plaintext or ciphertext is placed into the most-significant byte of D. We use (A;B;C;D) = (B;C;D;A) to mean the parallel assignment of values on the right to registers on the left.
	1.open input.txt or input_d.txt
	2.read data,get the mode (encryption or decryption)
	3.read data,get the paintext or ciphertext,and get userkey
	4.setup key and encryption or decryption
	5.open output.txt or output_d.txt,write ciphertext to output.txt or write plaintext to output_d.txt
