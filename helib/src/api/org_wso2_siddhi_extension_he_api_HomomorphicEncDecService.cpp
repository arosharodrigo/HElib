#include <cstring>
#include "EncryptedArray.h"
#include "FHE.h"
#include <fstream>
#include <NTL/ZZX.h>
#include <iostream>
#include <iterator>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>

#include "org_wso2_siddhi_extension_he_api_HomomorphicEncDecService.h"
#include "myUtils.h"

string localKeyFileLocation = "/home/arosha/helib-keys";
string publicKeyFileName = "pubkey.txt";
string securityKeyFileName = "seckey.txt";

FHEcontext* globalContext;
FHEPubKey* globalPublicKey;
FHESecKey* globalSecretKey;

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_init
(JNIEnv * env, jobject jobj, jstring keyFileLocation) {

	const char *cstr = env->GetStringUTFChars(keyFileLocation, NULL);
	std::string str = std::string(cstr);
	env->ReleaseStringUTFChars(keyFileLocation, cstr);
	localKeyFileLocation = str;

	Timer timer1;
	timer1.start();
	fstream pubKeyFile(localKeyFileLocation + "/" + publicKeyFileName, fstream::in);
	assert(pubKeyFile.is_open());
	unsigned long m, p, r;
	vector<long> gens, ords;
	readContextBase(pubKeyFile, m, p, r, gens, ords);
	globalContext = new FHEcontext(m, p, r, gens, ords);
	pubKeyFile >> *globalContext;
	globalPublicKey = new FHEPubKey(*globalContext);
	pubKeyFile >> *globalPublicKey;
	pubKeyFile.close();

	fstream secKeyFile(localKeyFileLocation + "/" + securityKeyFileName, fstream::in);
	globalSecretKey = new FHESecKey(*globalContext);
	secKeyFile >> *globalSecretKey;

	timer1.stop();
	std::cout << "Time for context creation [HomomorphicEncDecService]: " << timer1.elapsed_time() << "s" << std::endl;
}

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_destroy
(JNIEnv * env, jobject jobj) {
	// Nothing to do
}

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_generateKeys
(JNIEnv * env, jobject jobj, jstring keyFileLocation, jlong p, jlong r, jlong L, jlong c, jlong w, jlong d, jlong k, jlong s) {

	const char *cstr = env->GetStringUTFChars(keyFileLocation, NULL);
	std::string str = std::string(cstr);
	env->ReleaseStringUTFChars(keyFileLocation, cstr);
	localKeyFileLocation = str;

	long m = 0;    				// Specific modulus
	long local_p = (long) p;    // Plaintext base [default=2], should be a prime number
	long local_r = (long) r;    // Lifting [default=1]
	long local_L = (long) L;    // Number of levels in the modulus chain [default=heuristic]
	long local_c = (long) c;    // Number of columns in key-switching matrix [default=2]
	long local_w = (long) w;    // Hamming weight of secret key
	long local_d = (long) d;    // Degree of the field extension [default=1]
	long local_k = (long) k;    // Security parameter [default=80]
	long local_s = (long) s;    // Minimum number of slots [default=0]

	m = FindM(local_k, local_L, local_c, local_p, local_d, local_s, 0);

	cout << "Calculated M:" << m << "\n";

	ZZX G;
	G = makeIrredPoly(local_p, 1);

	FHEcontext context(m, local_p, local_r);
	buildModChain(context, local_L, local_c);

	FHESecKey secretKey(context);
	const FHEPubKey& publicKey = secretKey;
	secretKey.GenSecKey(local_w);
	addSome1DMatrices(secretKey);

	EncryptedArray ea(context, G);
	long nslots = ea.size();
	cout << "nslots:" << nslots << "\n";

	// Write context and public key
	fstream pubKeyFile(localKeyFileLocation + "/" + publicKeyFileName, fstream::out|fstream::trunc);
	assert(pubKeyFile.is_open());
	writeContextBase(pubKeyFile, context);
	pubKeyFile << context << std::endl;
	pubKeyFile << publicKey << std::endl;
	pubKeyFile.close();

	// Write context and security key
	fstream secKeyFile(localKeyFileLocation + "/" + securityKeyFileName, fstream::out|fstream::trunc);
	assert(secKeyFile.is_open());
	secKeyFile << secretKey << std::endl;
	secKeyFile.close();
}

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_encryptLong
(JNIEnv * env, jobject jobj, jlong val) {
	EncryptedArray ea(*globalContext);
	NewPlaintextArray npa(ea);
	encode(ea, npa, to_ZZX((long)val));
	Ctxt encryptedVal(*globalPublicKey);
	ea.encrypt(encryptedVal, *globalPublicKey, npa);

	stringstream ssEncryptedVal;
	ssEncryptedVal << encryptedVal;
	jstring encryptedStr = env->NewStringUTF(ssEncryptedVal.str().c_str());
	return encryptedStr;
}

JNIEXPORT jlong JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_decryptLong
(JNIEnv * env, jobject jobj, jstring encryptedVal) {
	EncryptedArray ea(*globalContext);
	Ctxt encryptedValCyper(*globalPublicKey);

	const char *cstr = env->GetStringUTFChars(encryptedVal, NULL);
	std::string encryptedValStr = std::string(cstr);
	env->ReleaseStringUTFChars(encryptedVal, cstr);
	stringstream ssEncryptedVal(encryptedValStr);
	ssEncryptedVal >> encryptedValCyper;

	NewPlaintextArray npa(ea);
	ea.decrypt(encryptedValCyper, *globalSecretKey, npa);
	vector<ZZX> decryptedVector;
	decode(ea, decryptedVector, npa);
	long decryptedNumber = 0;
	conv(decryptedNumber, decryptedVector[0][0]);
	return decryptedNumber;
}

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_encryptLongVector
(JNIEnv * env, jobject jobj, jstring val) {
//	Timer timer2;
//	timer2.start();

	EncryptedArray ea(*globalContext);
	NewPlaintextArray npa(ea);

	vector<ZZX> zzxVec;
	const char *cstr = env->GetStringUTFChars(val, NULL);
	std::vector<std::string> tokens;
	boost::split(tokens, cstr, boost::is_any_of(","), boost::token_compress_on);
	env->ReleaseStringUTFChars(val, cstr);

	for(int i = 0;i < tokens.size(); i++){
		zzxVec.push_back(to_ZZX(atol(tokens[i].c_str())));
	}
	encode(ea, npa, zzxVec);
	Ctxt encryptedVal(*globalPublicKey);
//	timer2.stop();
//	std::cout << "Time for preparation: " << timer2.elapsed_time() << "s" << std::endl;

//	Timer tEncryption;
//	tEncryption.start();
	ea.encrypt(encryptedVal, *globalPublicKey, npa);
//	tEncryption.stop();
//	std::cout << "Time for encryption: " << tEncryption.elapsed_time() << "s" << std::endl;

	stringstream ssEncryptedVal;
	ssEncryptedVal << encryptedVal;
	jstring encryptedStr = env->NewStringUTF(ssEncryptedVal.str().c_str());
	return encryptedStr;
}

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_decryptLongVector
(JNIEnv * env, jobject jobj, jstring encryptedVal) {
	EncryptedArray ea(*globalContext);
	Ctxt encryptedValCyper(*globalPublicKey);

	const char *cstr = env->GetStringUTFChars(encryptedVal, NULL);
	std::string encryptedValStr = std::string(cstr);
	env->ReleaseStringUTFChars(encryptedVal, cstr);

	stringstream ssEncryptedVal(encryptedValStr);
	ssEncryptedVal >> encryptedValCyper;

	NewPlaintextArray npa(ea);
	ea.decrypt(encryptedValCyper, *globalSecretKey, npa);
	vector<ZZX> decryptedVector;
	decode(ea, decryptedVector, npa);

	vector<long> decryptedNumbers(decryptedVector.size());
	for(int i = 0;i < decryptedVector.size(); i++) {
		if(decryptedVector[i] == 0) {
			conv(decryptedNumbers[i], 0);
		} else {
			conv(decryptedNumbers[i], decryptedVector[i][0]);
		}
	}
	std::stringstream result;
	std::copy(decryptedNumbers.begin(), decryptedNumbers.end(), std::ostream_iterator<long>(result, ","));

	jstring orb_string = env->NewStringUTF(result.str().c_str());
	return orb_string;
}

