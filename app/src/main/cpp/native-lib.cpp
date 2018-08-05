#include <jni.h>
#include <string>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
    之前生成好的签名字符串
*/
const char *DEBUG_SIGN = "308201dd30820146020101300d06092a864886f70d010105050030373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b3009060355040613025553301e170d3137303431333032313430335a170d3437303430363032313430335a30373116301406035504030c0d416e64726f69642044656275673110300e060355040a0c07416e64726f6964310b300906035504061302555330819f300d06092a864886f70d010101050003818d003081890281810097a76b405d35f468c43eaeee0156b8b38e889c508b77964bd5db89cc107928a9aa79420ef280931fcd20cf481d6d2de4b99ab35d652bd59106823348ea5eaf7450ba504e8f04c918ad487b856010c48798aa233010432c238da9bae014ee2d24104fc7a6fa36f1bfd22360e9ef5998d12e724b7f21b8e40361afa0415d32f0390203010001300d06092a864886f70d010105050003818100785088366a568bf92f2e227488c6eb8742b59b10de5231908fe5212a1ad4642983cd6bbca7dcdc493f68113497869098ff7ea6a4b3fdd1a6c81b9425d1776b070c8ce3b32d5560d650ab866f62539c11b457a95c6bc2466959f5789c12cba29993178896dd5e26bdc66524e173e99b6d088f09ee985ade8a34c7c3e1549fbbef";
const char *RELEASE_SIGN = "308202b9308201a1a00302010202041daafed0300d06092a864886f70d01010b0500300d310b3009060355040613023836301e170d3138303331333039303034355a170d3433303330373039303034355a300d310b300906035504061302383630820122300d06092a864886f70d01010105000382010f003082010a02820101009edbf86fd0a833464cf7914216256e968bbf2e3cb1e92438120a25103952417ce10245000870cff4ae48f642958f9bd3441b008b9b0b6b8a15c372f11a64169353e19787189e8cbfc9ae0d56d3ff0bcc75670b8fe03da95261348e7da9ee7e2124870970bc5dd77a0e02048091043bae29ec560b77c4c81c62ac7df8529d3f3a8c1c1f4826441847c5f17a84108825043b8e868ef3c8f45ab92f935da6883f541e4c34947cd6f528685ed8939f55d917f054554e2e985d810d39d2d5b4117c9defe1b6f5f05047c19ce6d17702ef5dacd38e26d4eadb7731c9f60bee050d9fe677b8c409bd21d37c42a2985e58eda0d73d7216f1c58fcb19d698b9f0dc84a1e90203010001a321301f301d0603551d0e04160414b7a3543cf560ac193a7efa20381b675fc897db64300d06092a864886f70d01010b0500038201010027e0e65a5e13bd4fc998c7ea351f0b53545f05365bc6b120ca0cb33d7abe38fa341417332ceacf665366e94f1518a653bbb3b1a69756d7eaaa8a9dd132a68e1d0dc4d96997dd36566465b6dca7da3dedb2e70d3492af6a4777e5c607609c281d0be8f6ec19f6586cc6984f472ad70af5dac2ec111511d5170e3bf422d5c5096816481ff39e2c40f170d04e3faba13648323b5b7a698b1f6565e6aee6f09c649d8f7be4ba35f3db4cc0bd073d23a02e6072e63afdccf16fa3178e6900916700a342ba570fd4dfbc9a79256fe0ad19ae278e4ee818ec3cf9eaa17f0c12edb234e8ce20a03a1064012bca9138a0df8110950d8dcade37f203c7b66688b5b9e750ca";
const char *AUTH_KEY = "1234567812345678";
const char *IV = "1234567812345678";

/**
 * 拿到传入的app  的 签名信息，对比合法的app 签名，防止so文件被未知应用盗用
 */
//static jclass contextClass;
//static jclass signatureClass;
//static jclass packageNameClass;
//static jclass packageInfoClass;

JNIEXPORT jstring JNICALL
Java_com_hengsheng_sodemo_NativeUtils_getKey(JNIEnv *env, jclass jclazz, jobject contextObject) {
    jclass native_class = env->GetObjectClass(contextObject);
    jmethodID pm_id = env->GetMethodID(native_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pm_obj = env->CallObjectMethod(contextObject, pm_id);
    jclass pm_clazz = env->GetObjectClass(pm_obj);
    // 得到 getPackageInfo 方法的 ID
    jmethodID package_info_id = env->GetMethodID(pm_clazz, "getPackageInfo","(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jclass native_classs = env->GetObjectClass(contextObject);
    jmethodID mId = env->GetMethodID(native_classs, "getPackageName", "()Ljava/lang/String;");
    jstring pkg_str = static_cast<jstring>(env->CallObjectMethod(contextObject, mId));
    // 获得应用包的信息
    jobject pi_obj = env->CallObjectMethod(pm_obj, package_info_id, pkg_str, 64);
    //获得 PackageInfo 类
    jclass pi_clazz = env->GetObjectClass(pi_obj);
    // 获得签名数组属性的 ID
    jfieldID signatures_fieldId = env->GetFieldID(pi_clazz, "signatures", "[Landroid/content/pm/Signature;");
    jobject signatures_obj = env->GetObjectField(pi_obj, signatures_fieldId);
    jobjectArray signaturesArray = (jobjectArray)signatures_obj;
    jsize size = env->GetArrayLength(signaturesArray);
    jobject signature_obj = env->GetObjectArrayElement(signaturesArray, 0);
    jclass signature_clazz = env->GetObjectClass(signature_obj);
    jmethodID string_id = env->GetMethodID(signature_clazz, "toCharsString", "()Ljava/lang/String;");
    jstring str = static_cast<jstring>(env->CallObjectMethod(signature_obj, string_id));
    char *c_msg = (char*)env->GetStringUTFChars(str,0);
    //return str;
    if(strcmp(c_msg,DEBUG_SIGN)==0)//签名一致 返回合法的 api key，否则返回错误
    {
        return (env)->NewStringUTF(AUTH_KEY);
    }else if (strcmp(c_msg,RELEASE_SIGN)==0)
    {
        return (env)->NewStringUTF(AUTH_KEY);
    } else {
        return (env)->NewStringUTF("error");
    }
};

JNIEXPORT jstring JNICALL
Java_com_hengsheng_sodemo_NativeUtils_getIv(JNIEnv *env, jclass jclazz, jobject contextObject) {
    jclass native_class = env->GetObjectClass(contextObject);
    jmethodID pm_id = env->GetMethodID(native_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pm_obj = env->CallObjectMethod(contextObject, pm_id);
    jclass pm_clazz = env->GetObjectClass(pm_obj);
    // 得到 getPackageInfo 方法的 ID
    jmethodID package_info_id = env->GetMethodID(pm_clazz, "getPackageInfo","(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jclass native_classs = env->GetObjectClass(contextObject);
    jmethodID mId = env->GetMethodID(native_classs, "getPackageName", "()Ljava/lang/String;");
    jstring pkg_str = static_cast<jstring>(env->CallObjectMethod(contextObject, mId));
    // 获得应用包的信息
    jobject pi_obj = env->CallObjectMethod(pm_obj, package_info_id, pkg_str, 64);
    //获得 PackageInfo 类
    jclass pi_clazz = env->GetObjectClass(pi_obj);
    // 获得签名数组属性的 ID
    jfieldID signatures_fieldId = env->GetFieldID(pi_clazz, "signatures", "[Landroid/content/pm/Signature;");
    jobject signatures_obj = env->GetObjectField(pi_obj, signatures_fieldId);
    jobjectArray signaturesArray = (jobjectArray)signatures_obj;
    jsize size = env->GetArrayLength(signaturesArray);
    jobject signature_obj = env->GetObjectArrayElement(signaturesArray, 0);
    jclass signature_clazz = env->GetObjectClass(signature_obj);
    jmethodID string_id = env->GetMethodID(signature_clazz, "toCharsString", "()Ljava/lang/String;");
    jstring str = static_cast<jstring>(env->CallObjectMethod(signature_obj, string_id));
    char *c_msg = (char*)env->GetStringUTFChars(str,0);
    //return str;
    if(strcmp(c_msg,DEBUG_SIGN)==0)//签名一致 返回合法的 api key，否则返回错误
    {
        return (env)->NewStringUTF(IV);
    }else if (strcmp(c_msg,RELEASE_SIGN)==0)
    {
        return (env)->NewStringUTF(IV);
    } else {
        return (env)->NewStringUTF("error");
    }
};


JNIEXPORT jint JNICALL JNI_OnLoad (JavaVM* vm,void* reserved){

    JNIEnv* env = NULL;
    jint result=-1;
    if(vm->GetEnv((void**)&env, JNI_VERSION_1_4) != JNI_OK)
        return result;

    jclass contextClass = (jclass)env->NewGlobalRef((env)->FindClass("android/content/Context"));
    jclass signatureClass = (jclass)env->NewGlobalRef((env)->FindClass("android/content/pm/Signature"));
    jclass packageNameClass = (jclass)env->NewGlobalRef((env)->FindClass("android/content/pm/PackageManager"));
    jclass packageInfoClass = (jclass)env->NewGlobalRef((env)->FindClass("android/content/pm/PackageInfo"));

    return JNI_VERSION_1_4;
}

#ifdef __cplusplus
}
#endif

extern "C"
JNIEXPORT jstring JNICALL
Java_com_hengsheng_sodemo_NativeUtils_getMyName(JNIEnv *env, jclass type) {
    return env->NewStringUTF("张宝");
}
