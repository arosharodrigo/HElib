
#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>

#include <cassert>
#include <cstdio>

#include <array>
#include <memory>
#include <type_traits>
#include <iostream>
#include <iomanip>

using byte = unsigned char ;

template< typename T > std::array< byte, sizeof(T) >  to_bytes( const T& object )
{
    std::array< byte, sizeof(T) > bytes ;

    const byte* begin = reinterpret_cast< const byte* >( std::addressof(object) ) ;
    const byte* end = begin + sizeof(T) ;
    std::copy( begin, end, std::begin(bytes) ) ;

    return bytes ;
}

template< typename T >
T& from_bytes( const std::array< byte, sizeof(T) >& bytes, T& object )
{
    // http://en.cppreference.com/w/cpp/types/is_trivially_copyable
    static_assert( std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type" ) ;

    byte* begin_object = reinterpret_cast< byte* >( std::addressof(object) ) ;
    std::copy( std::begin(bytes), std::end(bytes), begin_object ) ;

    return object ;
}

void  TestIt(long m, long p, long r, long L, long c, long w) {
	ZZX G;
	G = makeIrredPoly(p, 1);

	FHEcontext context(m, p, r);
	buildModChain(context, L, c);

	FHESecKey secretKey(context);
	// construct a secret key structure associated with the context
	const FHEPubKey& publicKey = secretKey;
	// an "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(w);
	// actually generate a secret key with Hamming weight w
	addSome1DMatrices(secretKey);
	// compute key-switching matrices that we need
	EncryptedArray ea(context, G);
	// constuct an Encrypted array object ea that is
	// associated with the given context and the polynomial G
	long nslots = ea.size();
	// number of plaintext slots
	NewPlaintextArray p0(ea);
	NewPlaintextArray p1(ea);
	NewPlaintextArray p2(ea);
	NewPlaintextArray p3(ea);
	// NewPlaintextArray objects associated with the given EncryptedArray ea

	random(ea, p0);
	random(ea, p1);
	random(ea, p2);
	random(ea, p3);

	cout << "p0-before:\n" << p0;
//	cout << "p1" << p1;
//	cout << "p2" << p2;
//	cout << "p3" << p3;

	// generate random plaintexts: slots initalized with random elements of Z[X]/(G,p^r)
	Ctxt c0(publicKey), c1(publicKey), c2(publicKey), c3(publicKey);
	// construct ciphertexts associated with the given public key
	ea.encrypt(c0, publicKey, p0);
	ea.encrypt(c1, publicKey, p1);
	ea.encrypt(c2, publicKey, p2);
	ea.encrypt(c3, publicKey, p3);
	// encrypt each NewPlaintextArray

//	cout << "c0" << c0;
//	cout << "c1" << c1;
//	cout << "c2" << c2;
//	cout << "c3" << c3;

	long shamt = RandomBnd(2*(nslots/2) + 1) - (nslots/2);
	// shift-amount: random number in [-nslots/2..nslots/2]
	long rotamt = RandomBnd(2*nslots - 1) - (nslots - 1);
	// rotation-amount: random number in [-(nslots-1)..nslots-1]
	NewPlaintextArray const1(ea);
	NewPlaintextArray const2(ea);
	random(ea, const1);
	random(ea, const2);
	// two random constants

	// Perform some simple computations directly on the plaintext arrays:
	mul(ea, p1, p0); // p1 = p1 * p0 (slot-wise modulo G)
	add(ea, p0, const1); // p0 = p0 + const1
	mul(ea, p2, const2); // p2 = p2 * const2
	NewPlaintextArray tmp_p(p1); // tmp = p1
	shift(ea, tmp_p, shamt); // shift tmp_p by shamt
	add(ea, p2, tmp_p); // p2 = p2 + tmp_p
	rotate(ea, p2, rotamt); // rotate p2 by rotamt
	::negate(ea, p1); // p1 = - p1
	mul(ea, p3, p2); // p3 = p3 * p2
	sub(ea, p0, p3); // p0 = p0 - p3

	// Perform the same operations on the ciphertexts
	ZZX const1_poly, const2_poly;
	ea.encode(const1_poly, const1);
	ea.encode(const2_poly, const2);
	// encode const1 and const2 as plaintext polynomials
	c1.multiplyBy(c0); // c1 = c1 * c0
	c0.addConstant(const1_poly); // c0 = c0 + const1
	c2.multByConstant(const2_poly); // c2 = c2 * const2

	Ctxt tmp(c1); // tmp = c1
	ea.shift(tmp, shamt); // shift tmp by shamt
	c2 += tmp; // c2 = c2 + tmp
	ea.rotate(c2, rotamt); // rotate c2 by shamt
	c1.negate(); // c1 = - c1
	c3.multiplyBy(c2); // c3 = c3 * c2
	c0 -= c3; // c0 = c0 - c3
	// Decrypt the ciphertexts and compare

	NewPlaintextArray pp0(ea);
	NewPlaintextArray pp1(ea);
	NewPlaintextArray pp2(ea);
	NewPlaintextArray pp3(ea);

	ea.decrypt(c0, secretKey, pp0);
	ea.decrypt(c1, secretKey, pp1);
	ea.decrypt(c2, secretKey, pp2);
	ea.decrypt(c3, secretKey, pp3);

	if (!equals(ea, pp0, p0)) cerr << "oops 0\n";
	if (!equals(ea, pp1, p1)) cerr << "oops 1\n";
	if (!equals(ea, pp2, p2)) cerr << "oops 2\n";
	if (!equals(ea, pp3, p3)) cerr << "oops 3\n";

	if (equals(ea, pp0, p0)) cerr << "Good 0\n";
	if (equals(ea, pp1, p1)) cerr << "Good 1\n";
	if (equals(ea, pp2, p2)) cerr << "Good 2\n";
	if (equals(ea, pp3, p3)) cerr << "Good 3\n";

}

/*void  TestIt2() {
	long m = 0;    // Specific modulus
	long p = 1021; // Plaintext base [default=2], should be a prime number
	long r = 1;    // Lifting [default=1]
	long L = 16;   // Number of levels in the modulus chain [default=heuristic]
	long c = 3;    // Number of columns in key-switching matrix [default=2]
	long w = 64;   // Hamming weight of secret key
	long d = 0;    // Degree of the field extension [default=1]
	long k = 128;  // Security parameter [default=80]
	long s = 0;    // Minimum number of slots [default=0]

	m = FindM(k,L,c,p, d, s, 0);

	FHEcontext context(m, p, r);
	buildModChain(context, L, c);

	ZZX G = context.alMod.getFactorsOverZZ()[0];

	FHESecKey secretKey(context);
	const FHEPubKey&amp;
	publicKey = secretKey;
	secretKey.GenSecKey(w);

	Ctxt ctx1(publicKey);
	Ctxt ctx2(publicKey);

	publicKey.Encrypt(ctx1, to_ZZX(2));
	publicKey.Encrypt(ctx2, to_ZZX(3));

	Ctxt ctSum = ctx1;
	ctSum += ctx2;

	ZZX ptSum;
	secretKey.Decrypt(ptSum, ctSum);

	cout << ptSum;

}*/

void  TestIt3() {
	long m = 0;    // Specific modulus
	long p = 1021; // Plaintext base [default=2], should be a prime number
	long r = 1;    // Lifting [default=1]
	long L = 1;   // Number of levels in the modulus chain [default=heuristic]
	long c = 3;    // Number of columns in key-switching matrix [default=2]
	long w = 64;   // Hamming weight of secret key
	long d = 0;    // Degree of the field extension [default=1]
	long k = 128;  // Security parameter [default=80]
	long s = 0;    // Minimum number of slots [default=0]
	m = FindM(k, L, c, p, d, s, 0);

	ZZX G;
	G = makeIrredPoly(p, 1);

	FHEcontext context(m, p, r);
	buildModChain(context, L, c);

	FHESecKey secretKey(context);
	// construct a secret key structure associated with the context
	const FHEPubKey& publicKey = secretKey;
	// an "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(w);
	// actually generate a secret key with Hamming weight w
	addSome1DMatrices(secretKey);
	// compute key-switching matrices that we need
	EncryptedArray ea(context, G);
	// constuct an Encrypted array object ea that is
	// associated with the given context and the polynomial G
	long nslots = ea.size();
	// number of plaintext slots

	NewPlaintextArray p0(ea);
	// NewPlaintextArray objects associated with the given EncryptedArray ea
	random(ea, p0);
	// generate random plaintexts: slots initalized with random elements of Z[X]/(G,p^r)
	Ctxt c0(publicKey);
	// construct ciphertexts associated with the given public key
	ea.encrypt(c0, publicKey, p0);
	// encrypt each NewPlaintextArray

//	cout << "c0" << c0;

	NewPlaintextArray const1(ea);
	random(ea, const1);

	// Perform some simple computations directly on the plaintext arrays:

	cout << "p0-before:\n" << p0 << "\n";
	cout << "const1-before:\n" << const1 << "\n";

	add(ea, p0, const1); // p0 = p0 + const1
	cout << "p0\n" << p0 << "\n";

	// Perform the same operations on the ciphertexts
	std::vector<long> second (4,100);

	ZZX const1_poly;
	ea.encode(const1_poly, const1);

	c0.addConstant(const1_poly); // c0 = c0 + const1
	cout << "c0:\n" << c0 << "\n";
	cout << "const1_poly:\n" << const1_poly << "\n";


	// Decrypt the ciphertexts and compare
	NewPlaintextArray pp0(ea);

	ea.decrypt(c0, secretKey, pp0);

	if (!equals(ea, pp0, p0)) cerr << "oops 0\n";

	if (equals(ea, pp0, p0)) cerr << "Good 0\n";


//	cout << "pp0\n" << pp0 << "\n";

}

void convert(string key, string text) {

//	cout << "key:\n" << key << "\n";
//	cout << "text:\n" << text << "\n";

	FHEPubKey publicKey;
	stringstream sskey(key);
	sskey >> publicKey;

	//	oss2 << cStr;
//		Ctxt c10;
	//	oss2 >> c10;
//		ss2 >> c10;

//	cout << "c10:\n" << c10 << "\n";
}

void  TestIt4() {
	long m = 0;    // Specific modulus
	long p = 9576890767; // Plaintext base [default=2], should be a prime number
	long r = 1;    // Lifting [default=1]
	long L = 1;   // Number of levels in the modulus chain [default=heuristic]
	long c = 2;    // Number of columns in key-switching matrix [default=2]
	long w = 64;   // Hamming weight of secret key
	long d = 0;    // Degree of the field extension [default=1]
	long k = 128;  // Security parameter [default=80]
	long s = 0;    // Minimum number of slots [default=0]
	m = FindM(k, L, c, p, d, s, 0);

	ZZX G;
	G = makeIrredPoly(p, 1);

	FHEcontext context(m, p, r);
	buildModChain(context, L, c);

	FHESecKey secretKey(context);
	// construct a secret key structure associated with the context
	const FHEPubKey& publicKey = secretKey;
	// an "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(w);
	// actually generate a secret key with Hamming weight w
	addSome1DMatrices(secretKey);
	// compute key-switching matrices that we need
	EncryptedArray ea(context, G);
	// constuct an Encrypted array object ea that is
	// associated with the given context and the polynomial G
	long nslots = ea.size();
	// number of plaintext slots
	cout << "nslots:" << nslots << "\n";

	NewPlaintextArray p0(ea);
	// NewPlaintextArray objects associated with the given EncryptedArray ea
//	random(ea, p0);
	encode(ea, p0, to_ZZX(9));
	// generate random plaintexts: slots initalized with random elements of Z[X]/(G,p^r)
	Ctxt c0(publicKey);
	// construct ciphertexts associated with the given public key
	ea.encrypt(c0, publicKey, p0);
	// encrypt each NewPlaintextArray



	NewPlaintextArray p1(ea);
//	random(ea, p1);
	encode(ea, p1, to_ZZX(5));
	Ctxt c1(publicKey);
	ea.encrypt(c1, publicKey, p1);
	// Perform some simple computations directly on the plaintext arrays:

//	cout << "c0-before:" << c0;
//	cout << "c1-before:" << c1;

	cout << "p0-before:\n" << p0 << "\n";
	cout << "p1-before:\n" << p1 << "\n";

	add(ea, p0, p1); // p0 = p0 + const1
	cout << "p0:\n" << p0 << "\n";

	c0.addCtxt(c1); // c0 = c0 + const1
//	cout << "c0:\n" << c0 << "\n";


	// Decrypt the ciphertexts and compare
	NewPlaintextArray pp0(ea);

	ea.decrypt(c0, secretKey, pp0);
//	cout << "pp0:\n" << pp0 << "\n";

	if (!equals(ea, pp0, p0)) cerr << "oops 0\n";

	if (equals(ea, pp0, p0)) cerr << "Good 0\n";

	stringstream ssc0;
	ssc0 << c0;
	string sc0 = ssc0.str();

	stringstream sspublicKey;
	sspublicKey << publicKey;
	string spublicKey = sspublicKey.str();

//	cout << "c0:\n" << c0 << "\n";
	cout << "\n";

	convert(spublicKey, sc0);

}



int main(int argc, char *argv[]) {
//	TestIt(7781, 2, 1, 6, 2, 64);
//	TestIt3(7781, 2, 5, 6, 2, 64);
//	TestIt3();
//	TestIt2();
	TestIt4();
}

int main2()
{
//    double d = 123.456789 ;
//    const auto bytes = to_bytes(d) ;
//
//    std::cout << std::hex << std::setfill('0') ;
//    for( byte b : bytes ) std::cout << std::setw(2) << int(b) << ' ' ;
//    std::cout << '\n' ;
//
//    d = 0 ;
//    from_bytes( bytes, d ) ;
//    std::cout << std::fixed << d << '\n' ;
//
//
//    int arr[] = { 1, 63, 256, 511, 1024 } ;
//    const auto array_bytes = to_bytes(arr) ;
//
//    for( byte b : array_bytes ) std::cout << std::setw(2) << int(b) << ' ' ;
//    std::cout << '\n' ;
//
//    for( int& v : arr ) v = -1 ;
//    from_bytes( array_bytes, arr ) ;
//    for( int v : arr ) std::cout << std::dec << v << ' ' ;
//    std::cout << '\n' ;



}
