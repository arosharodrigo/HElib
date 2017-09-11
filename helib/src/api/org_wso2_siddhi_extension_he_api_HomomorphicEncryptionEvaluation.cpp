#include <cstring>
#include "EncryptedArray.h"
#include "FHE.h"
#include <fstream>
#include <NTL/ZZX.h>
#include <iostream>

#include "org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation.h"

string localKeyFileLocation2 = "";
string publicKeyFileName2 = "pubkey.txt";

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_init
(JNIEnv * env, jobject jobj, jstring keyFileLocation) {
	const char *cstr = env->GetStringUTFChars(keyFileLocation, NULL);
	std::string str = std::string(cstr);
	env->ReleaseStringUTFChars(keyFileLocation, cstr);
	localKeyFileLocation2 = str;
}

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_destroy
(JNIEnv * env, jobject jobj) {
	// Nothing to do
}

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_evaluateAdd
(JNIEnv * env, jobject jobj, jstring param1, jstring param2) {
	fstream pubKeyFile(localKeyFileLocation2 + "/" + publicKeyFileName2, fstream::in);
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

	Ctxt c1(publicKey);
	const char *cstr1 = env->GetStringUTFChars(param1, NULL);
	std::string str1 = std::string(cstr1);
	env->ReleaseStringUTFChars(param1, cstr1);
	stringstream ssparam1(str1);
	ssparam1 >> c1;

	Ctxt c2(publicKey);
	const char *cstr2 = env->GetStringUTFChars(param2, NULL);
	std::string str2 = std::string(cstr2);
	env->ReleaseStringUTFChars(param2, cstr2);
	stringstream ssparam2(str2);
	ssparam2 >> c2;

	c1.addCtxt(c2);

	stringstream ssResult;
	ssResult << c1;
	jstring resultStr = env->NewStringUTF(ssResult.str().c_str());
	return resultStr;
}
