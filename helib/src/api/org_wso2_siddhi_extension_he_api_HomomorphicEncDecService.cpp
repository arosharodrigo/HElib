#include <cstring>
#include "EncryptedArray.h"
#include "FHE.h"
#include <fstream>
#include <NTL/ZZX.h>
#include <iostream>

#include "org_wso2_siddhi_extension_he_api_HomomorphicEncDecService.h"

string localKeyFileLocation = "";
string publicKeyFileName = "pubkey.txt";
string securityKeyFileName = "seckey.txt";

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_init
(JNIEnv * env, jobject jobj, jstring keyFileLocation) {
	const char *cstr = env->GetStringUTFChars(keyFileLocation, NULL);
	std::string str = std::string(cstr);
	env->ReleaseStringUTFChars(keyFileLocation, cstr);
	localKeyFileLocation = str;
}

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_destroy
(JNIEnv * env, jobject jobj) {
	// Nothing to do
}

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_generateKeys
(JNIEnv * env, jobject jobj, jlong p, jlong r, jlong L, jlong c, jlong w, jlong d, jlong k, jlong s) {
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
	fstream pubKeyFile(localKeyFileLocation + "/" + publicKeyFileName, fstream::in);
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

	NewPlaintextArray npa(ea);
	encode(ea, npa, to_ZZX((long)val));
	Ctxt encryptedVal(publicKey);
	ea.encrypt(encryptedVal, publicKey, npa);

	stringstream ssEncryptedVal;
	ssEncryptedVal << encryptedVal;
	jstring encryptedStr = env->NewStringUTF(ssEncryptedVal.str().c_str());
	return encryptedStr;
}

JNIEXPORT jlong JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncDecService_decryptLong
(JNIEnv * env, jobject jobj, jstring encryptedVal) {
	fstream pubKeyFile(localKeyFileLocation + "/" + publicKeyFileName, fstream::in);
	assert(pubKeyFile.is_open());
	unsigned long m, p, r;
	vector<long> gens, ords;
	readContextBase(pubKeyFile, m, p, r, gens, ords);
	FHEcontext context(m, p, r, gens, ords);
	pubKeyFile >> context;
	FHEPubKey publicKey(context);
	pubKeyFile >> publicKey;
	pubKeyFile.close();

	fstream secKeyFile(localKeyFileLocation + "/" + securityKeyFileName, fstream::in);
	FHESecKey secretKey(context);
	secKeyFile >> secretKey;

	EncryptedArray ea(context);

	Ctxt encryptedValCyper(publicKey);

	const char *cstr = env->GetStringUTFChars(encryptedVal, NULL);
	std::string encryptedValStr = std::string(cstr);
	env->ReleaseStringUTFChars(encryptedVal, cstr);
	stringstream ssEncryptedVal(encryptedValStr);
	ssEncryptedVal >> encryptedValCyper;

	NewPlaintextArray npa(ea);
	ea.decrypt(encryptedValCyper, secretKey, npa);
	vector<ZZX> decryptedVector;
	decode(ea, decryptedVector, npa);
	long decryptedNumber = 0;
	conv(decryptedNumber, decryptedVector[0][0]);
	return decryptedNumber;
}
