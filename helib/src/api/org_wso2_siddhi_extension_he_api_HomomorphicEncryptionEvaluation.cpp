#include <cstring>
#include "EncryptedArray.h"
#include "FHE.h"
#include <fstream>
#include <NTL/ZZX.h>
#include <iostream>

#include "org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation.h"
#include "myUtils.h"

string localKeyFileLocation2 = "/home/arosha/helib-keys";
string publicKeyFileName2 = "pubkey.txt";

FHEcontext* globalContext2;
FHEPubKey* globalPublicKey2;

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_init
(JNIEnv * env, jobject jobj, jstring keyFileLocation) {
	const char *cstr = env->GetStringUTFChars(keyFileLocation, NULL);
	std::string str = std::string(cstr);
	env->ReleaseStringUTFChars(keyFileLocation, cstr);
	localKeyFileLocation2 = str;

	Timer timer1;
	timer1.start();
	fstream pubKeyFile(localKeyFileLocation2 + "/" + publicKeyFileName2, fstream::in);
	assert(pubKeyFile.is_open());
	unsigned long m, p, r;
	vector<long> gens, ords;
	readContextBase(pubKeyFile, m, p, r, gens, ords);
	globalContext2 = new FHEcontext(m, p, r, gens, ords);
	pubKeyFile >> *globalContext2;
	globalPublicKey2 = new FHEPubKey(*globalContext2);
	pubKeyFile >> *globalPublicKey2;
	pubKeyFile.close();
	timer1.stop();
	std::cout << "Time for context creation [HomomorphicEncryptionEvaluation]: " << timer1.elapsed_time() << "s" << std::endl;
}

JNIEXPORT void JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_destroy
(JNIEnv * env, jobject jobj) {
	// Nothing to do
}

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_evaluateAdd
(JNIEnv * env, jobject jobj, jstring param1, jstring param2) {
	EncryptedArray ea(*globalContext2);
	Ctxt c1(*globalPublicKey2);

	const char *cstr1 = env->GetStringUTFChars(param1, NULL);
	std::string str1 = std::string(cstr1);
	env->ReleaseStringUTFChars(param1, cstr1);
	stringstream ssparam1(str1);
	ssparam1 >> c1;

	Ctxt c2(*globalPublicKey2);
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

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_evaluateSubtract
(JNIEnv * env, jobject jobj, jstring param1, jstring param2) {
	EncryptedArray ea(*globalContext2);
	Ctxt c1(*globalPublicKey2);

	const char *cstr1 = env->GetStringUTFChars(param1, NULL);
	std::string str1 = std::string(cstr1);
	env->ReleaseStringUTFChars(param1, cstr1);
	stringstream ssparam1(str1);
	ssparam1 >> c1;

	Ctxt c2(*globalPublicKey2);
	const char *cstr2 = env->GetStringUTFChars(param2, NULL);
	std::string str2 = std::string(cstr2);
	env->ReleaseStringUTFChars(param2, cstr2);
	stringstream ssparam2(str2);
	ssparam2 >> c2;

	c1.addCtxt(c2, true);

	stringstream ssResult;
	ssResult << c1;
	jstring resultStr = env->NewStringUTF(ssResult.str().c_str());
	return resultStr;
}

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_evaluateGreaterThanBitSize1
		(JNIEnv * env, jobject jobj, jstring param1bit1, jstring param2bit1) {

    EncryptedArray ea(*globalContext2);

    Ctxt c1(*globalPublicKey2);
	const char *cstr1 = env->GetStringUTFChars(param1bit1, NULL);
	std::string str1 = std::string(cstr1);
	env->ReleaseStringUTFChars(param1bit1, cstr1);
	stringstream ssparam1(str1);
	ssparam1 >> c1;

	Ctxt c2(*globalPublicKey2);
	const char *cstr2 = env->GetStringUTFChars(param2bit1, NULL);
	std::string str2 = std::string(cstr2);
	env->ReleaseStringUTFChars(param2bit1, cstr2);
	stringstream ssparam2(str2);
	ssparam2 >> c2;

    Ctxt c11(c1);

	c11 *= c2;
    c1.addCtxt(c11);

	stringstream ssResult;
	ssResult << c1;
	jstring resultStr = env->NewStringUTF(ssResult.str().c_str());
	return resultStr;
}

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_evaluateGreaterThanBitSize2
		(JNIEnv * env, jobject jobj, jstring param1bit1, jstring param1bit2, jstring param2bit1, jstring param2bit2) {

	EncryptedArray ea(*globalContext2);

	Ctxt x0(*globalPublicKey2);
	const char *cstr1 = env->GetStringUTFChars(param1bit1, NULL);
	std::string str1 = std::string(cstr1);
	env->ReleaseStringUTFChars(param1bit1, cstr1);
	stringstream ssparam1(str1);
	ssparam1 >> x0;

	Ctxt x1(*globalPublicKey2);
	const char *cstr2 = env->GetStringUTFChars(param1bit2, NULL);
	std::string str2 = std::string(cstr2);
	env->ReleaseStringUTFChars(param1bit2, cstr2);
	stringstream ssparam2(str2);
	ssparam2 >> x1;

	Ctxt y0(*globalPublicKey2);
	const char *cstr3 = env->GetStringUTFChars(param2bit1, NULL);
	std::string str3 = std::string(cstr3);
	env->ReleaseStringUTFChars(param2bit1, cstr3);
	stringstream ssparam3(str3);
	ssparam3 >> y0;

	Ctxt y1(*globalPublicKey2);
	const char *cstr4 = env->GetStringUTFChars(param2bit2, NULL);
	std::string str4 = std::string(cstr4);
	env->ReleaseStringUTFChars(param2bit2, cstr4);
	stringstream ssparam4(str4);
	ssparam4 >> y1;

	Ctxt x0copy1(x0);

	Ctxt x1copy1(x1);
	Ctxt x1copy2(x1);
	Ctxt x1copy3(x1);

	Ctxt y1copy1(y1);
	Ctxt y1copy2(y1);

    x1copy1 *= y1;

    x1copy2 *= x0;
    x1copy2 *= y0;

    x1copy3 *= x0;

    y1copy1 *= x0;
    y1copy1 *= y0;

    y1copy2 *= x0;

    x0copy1 *= y0;

    x1copy1.addCtxt(x1);
    x1copy1.addCtxt(x1copy2);
    x1copy1.addCtxt(x1copy3);
    x1copy1.addCtxt(y1copy1);
    x1copy1.addCtxt(y1copy2);
    x1copy1.addCtxt(x0copy1);
    x1copy1.addCtxt(x0);
    // x1copy1 has greater than result as of now

	stringstream ssResult;
	ssResult << x1copy1;
	jstring resultStr = env->NewStringUTF(ssResult.str().c_str());
	return resultStr;
}

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_evaluateLessThanBitSize2
        (JNIEnv * env, jobject jobj, jstring param1bit1, jstring param1bit2, jstring param2bit1, jstring param2bit2) {

    EncryptedArray ea(*globalContext2);

    Ctxt x0(*globalPublicKey2);
    const char *cstr1 = env->GetStringUTFChars(param1bit1, NULL);
    std::string str1 = std::string(cstr1);
    env->ReleaseStringUTFChars(param1bit1, cstr1);
    stringstream ssparam1(str1);
    ssparam1 >> x0;

    Ctxt x1(*globalPublicKey2);
    const char *cstr2 = env->GetStringUTFChars(param1bit2, NULL);
    std::string str2 = std::string(cstr2);
    env->ReleaseStringUTFChars(param1bit2, cstr2);
    stringstream ssparam2(str2);
    ssparam2 >> x1;

    Ctxt y0(*globalPublicKey2);
    const char *cstr3 = env->GetStringUTFChars(param2bit1, NULL);
    std::string str3 = std::string(cstr3);
    env->ReleaseStringUTFChars(param2bit1, cstr3);
    stringstream ssparam3(str3);
    ssparam3 >> y0;

    Ctxt y1(*globalPublicKey2);
    const char *cstr4 = env->GetStringUTFChars(param2bit2, NULL);
    std::string str4 = std::string(cstr4);
    env->ReleaseStringUTFChars(param2bit2, cstr4);
    stringstream ssparam4(str4);
    ssparam4 >> y1;

    Ctxt x0copy1(x0);

    Ctxt x1copy1(x1);
    Ctxt x1copy2(x1);
    Ctxt x1copy3(x1);

    Ctxt y1copy1(y1);
    Ctxt y1copy2(y1);

    x1copy1 *= y1;

    x1copy2 *= x0;
    x1copy2 *= y0;

    x1copy3 *= x0;

    y1copy1 *= x0;
    y1copy1 *= y0;

    y1copy2 *= x0;

    x0copy1 *= y0;

    x1copy1.addCtxt(x1);
    x1copy1.addCtxt(x1copy2);
    x1copy1.addCtxt(x1copy3);
    x1copy1.addCtxt(y1copy1);
    x1copy1.addCtxt(y1copy2);
    x1copy1.addCtxt(x0copy1);
    x1copy1.addCtxt(x0);
    // x1copy1 has greater than result as of now

    Ctxt x0copy2(x0);
    Ctxt x0copy3(x0);
    Ctxt y0copy1(y0);
    Ctxt y0copy2(y0);


    x0copy2 *= x1;
    x0copy3 *= y1;
    y0copy1 *= x1;
    y0copy2 *= y1;

    x0copy2.addCtxt(x0copy3);
    x0copy2.addCtxt(x0);
    x0copy2.addCtxt(y0copy1);
    x0copy2.addCtxt(y0copy2);
    x0copy2.addCtxt(y0);
    x0copy2.addCtxt(x1);
    x0copy2.addCtxt(y1);

    NewPlaintextArray p0(ea);
    encode(ea, p0, to_ZZX(1));
    Ctxt num1(*globalPublicKey2);
    ea.encrypt(num1, *globalPublicKey2, p0);
    x0copy2.addCtxt(num1);
    // x0copy2 has equal result as of now

    x1copy1.addCtxt(x0copy2);
    x1copy1.addCtxt(num1);

    stringstream ssResult;
    ssResult << x1copy1;
    jstring resultStr = env->NewStringUTF(ssResult.str().c_str());
    return resultStr;
}

JNIEXPORT jstring JNICALL Java_org_wso2_siddhi_extension_he_api_HomomorphicEncryptionEvaluation_evaluateEqualBitSize2
		(JNIEnv * env, jobject jobj, jstring param1bit1, jstring param1bit2, jstring param2bit1, jstring param2bit2) {

	EncryptedArray ea(*globalContext2);

	Ctxt x0(*globalPublicKey2);
	const char *cstr1 = env->GetStringUTFChars(param1bit1, NULL);
	std::string str1 = std::string(cstr1);
	env->ReleaseStringUTFChars(param1bit1, cstr1);
	stringstream ssparam1(str1);
	ssparam1 >> x0;

	Ctxt x1(*globalPublicKey2);
	const char *cstr2 = env->GetStringUTFChars(param1bit2, NULL);
	std::string str2 = std::string(cstr2);
	env->ReleaseStringUTFChars(param1bit2, cstr2);
	stringstream ssparam2(str2);
	ssparam2 >> x1;

	Ctxt y0(*globalPublicKey2);
	const char *cstr3 = env->GetStringUTFChars(param2bit1, NULL);
	std::string str3 = std::string(cstr3);
	env->ReleaseStringUTFChars(param2bit1, cstr3);
	stringstream ssparam3(str3);
	ssparam3 >> y0;

	Ctxt y1(*globalPublicKey2);
	const char *cstr4 = env->GetStringUTFChars(param2bit2, NULL);
	std::string str4 = std::string(cstr4);
	env->ReleaseStringUTFChars(param2bit2, cstr4);
	stringstream ssparam4(str4);
	ssparam4 >> y1;

	Ctxt x0copy2(x0);
	Ctxt x0copy3(x0);
	Ctxt y0copy1(y0);
	Ctxt y0copy2(y0);

	x0copy2 *= x1;
	x0copy3 *= y1;
	y0copy1 *= x1;
	y0copy2 *= y1;

	x0copy2.addCtxt(x0copy3);
	x0copy2.addCtxt(x0);
	x0copy2.addCtxt(y0copy1);
	x0copy2.addCtxt(y0copy2);
	x0copy2.addCtxt(y0);
	x0copy2.addCtxt(x1);
	x0copy2.addCtxt(y1);

	NewPlaintextArray p0(ea);
	encode(ea, p0, to_ZZX(1));
	Ctxt num1(*globalPublicKey2);
	ea.encrypt(num1, *globalPublicKey2, p0);
	x0copy2.addCtxt(num1);
	// x0copy2 has equal result as of now

	stringstream ssResult;
	ssResult << x0copy2;
	jstring resultStr = env->NewStringUTF(ssResult.str().c_str());
	return resultStr;
}
