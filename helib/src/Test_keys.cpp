#include <cstring>
#include "EncryptedArray.h"
#include "FHE.h"
#include <fstream>
#include <NTL/ZZX.h>
#include <iostream>

void generateKeys() {
	long m = 0;    // Specific modulus
	long p = 1543; // Plaintext base [default=2], should be a prime number
	long r = 1;    // Lifting [default=1]
	long L = 1;    // Number of levels in the modulus chain [default=heuristic]
	long c = 2;    // Number of columns in key-switching matrix [default=2]
	long w = 64;   // Hamming weight of secret key
	long d = 0;    // Degree of the field extension [default=1]
	long k = 128;  // Security parameter [default=80]
	long s = 0;    // Minimum number of slots [default=0]
	m = FindM(k, L, c, p, d, s, 0);

	cout << "Calculated M:" << m << "\n";

	ZZX G;
	G = makeIrredPoly(p, 1);

	FHEcontext context(m, p, r);
	buildModChain(context, L, c);

	FHESecKey secretKey(context);
	const FHEPubKey& publicKey = secretKey;
	secretKey.GenSecKey(w);
	addSome1DMatrices(secretKey);

	EncryptedArray ea(context, G);
	long nslots = ea.size();
	cout << "nslots:" << nslots << "\n";

	// Write context and public key
	fstream pubKeyFile("/home/arosha/helib-keys/pubkey.txt", fstream::out|fstream::trunc);
	assert(pubKeyFile.is_open());
	writeContextBase(pubKeyFile, context);
	pubKeyFile << context << std::endl;
	pubKeyFile << publicKey << std::endl;
	pubKeyFile.close();

	// Write context and security key
	fstream secKeyFile("/home/arosha/helib-keys/seckey.txt", fstream::out|fstream::trunc);
	assert(secKeyFile.is_open());
	secKeyFile << secretKey << std::endl;
	secKeyFile.close();
}

void evaluateAdd(string param1, string param2, NewPlaintextArray p0, NewPlaintextArray p1) {

	cout << "param1.length: " << param1.length() << "\n";
	cout << "param2.length: " << param2.length() << "\n";

	fstream pubKeyFile("/home/arosha/helib-keys/pubkey.txt", fstream::in);
	assert(pubKeyFile.is_open());
	unsigned long m, p, r;
	vector<long> gens, ords;
	readContextBase(pubKeyFile, m, p, r, gens, ords);
	FHEcontext context(m, p, r, gens, ords);
	pubKeyFile >> context;
	FHEPubKey publicKey(context);
	pubKeyFile >> publicKey;
	pubKeyFile.close();

	fstream secKeyFile("/home/arosha/helib-keys/seckey.txt", fstream::in);
	FHESecKey secretKey(context);
	secKeyFile >> secretKey;

	EncryptedArray ea(context);
	uint nslots = ea.size();
	cout << "nslots:" << nslots << "\n";

	Ctxt c1(publicKey);
	stringstream ssparam1(param1);
	ssparam1 >> c1;

	Ctxt c2(publicKey);
	stringstream ssparam2(param2);
	ssparam2 >> c2;

	c1.addCtxt(c2);

	NewPlaintextArray pp0(ea);
	ea.decrypt(c1, secretKey, pp0);
	cout << "pp0:\n" << pp0 << "\n";

	add(ea, p0, p1);
	cout << "p0:\n" << p0 << "\n";

//	cout << "c1:\n" << c1 << "\n";

	if (!equals(ea, pp0, p0)) cerr << "oops 0\n";
	if (equals(ea, pp0, p0)) cerr << "Good 0\n";

	vector<ZZX> h1;
	decode(ea, h1, pp0);
	cout << "h1:\n" << h1[0][0] << "\n";
}

void encrypt() {
	fstream pubKeyFile("/home/arosha/helib-keys/pubkey.txt", fstream::in);
	assert(pubKeyFile.is_open());
	unsigned long m, p, r;
	vector<long> gens, ords;
	readContextBase(pubKeyFile, m, p, r, gens, ords);
	FHEcontext context(m, p, r, gens, ords);
	pubKeyFile >> context;
	FHEPubKey publicKey(context);
	pubKeyFile >> publicKey;
	pubKeyFile.close();

	EncryptedArray ea(context);
	uint nslots = ea.size();
	cout << "nslots:" << nslots << "\n";

	NewPlaintextArray p0(ea);
	encode(ea, p0, to_ZZX(879));
	Ctxt c0(publicKey);
	ea.encrypt(c0, publicKey, p0);

	NewPlaintextArray p1(ea);
	encode(ea, p1, to_ZZX(663));
	Ctxt c1(publicKey);
	ea.encrypt(c1, publicKey, p1);

	stringstream ssc0;
	ssc0 << c0;
	string sc0 = ssc0.str();

	stringstream ssc1;
	ssc1 << c1;
	string sc1 = ssc1.str();

	evaluateAdd(sc0, sc1, p0, p1);
}


int main(int argc, char *argv[]) {
	generateKeys();
	encrypt();
}
