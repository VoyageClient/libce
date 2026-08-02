/*
 * Copyright 2016 OpenMarket Ltd
 * Copyright 2016 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "olm_inbound_group_session.h"


/**
 * Release the session allocation made by initializeInboundGroupSessionMemory().<br>
 * This method MUST be called when java counter part account instance is done.
 */
JNIEXPORT void OLM_INBOUND_GROUP_SESSION_FUNC_DEF(releaseSessionJni)(JNIEnv *env, jobject thiz)
{
    OlmInboundGroupSession* sessionPtr = getInboundGroupSessionInstanceId(env,thiz);

    LOGD("## releaseSessionJni(): InBound group session IN");

    if (!sessionPtr)
    {
        LOGE("## releaseSessionJni(): failure - invalid inbound group session instance");
    }
    else
    {
        LOGD(" ## releaseSessionJni(): sessionPtr=%p", sessionPtr);
#ifdef ENABLE_JNI_LOG
        size_t retCode = olm_clear_inbound_group_session(sessionPtr);
        LOGD(" ## releaseSessionJni(): clear_inbound_group_session=%lu",(long unsigned int)(retCode));
#else
        olm_clear_inbound_group_session(sessionPtr);
#endif

        LOGD(" ## releaseSessionJni(): free IN");
        free(sessionPtr);
        LOGD(" ## releaseSessionJni(): free OUT");
    }
}

/**
 * Initialize a new inbound group session and return it to JAVA side.<br>
 * Since a C prt is returned as a jlong, special care will be taken
 * to make the cast (OlmInboundGroupSession* => jlong) platform independent.
 * @param aSessionKeyBuffer session key from an outbound session
 * @param isImported true when the session key has been retrieved from a backup
 * @return the initialized OlmInboundGroupSession* instance or throw an exception it fails.
 **/
JNIEXPORT jlong OLM_INBOUND_GROUP_SESSION_FUNC_DEF(createNewSessionJni)(JNIEnv *env, jobject thiz, jbyteArray aSessionKeyBuffer, jboolean isImported)
{
    const char* errorMessage = NULL;
    OlmInboundGroupSession* sessionPtr = NULL;
    jbyte* sessionKeyPtr = NULL;
    jboolean sessionWasCopied = JNI_FALSE;
    size_t sessionSize = olm_inbound_group_session_size();

    LOGD("## createNewSessionJni(): inbound group session IN");

    if (!sessionSize)
    {
        LOGE(" ## createNewSessionJni(): failure - inbound group session size = 0");
        errorMessage = "inbound group session size = 0";
    }
    else if (!(sessionPtr = (OlmInboundGroupSession*)malloc(sessionSize)))
    {
        LOGE(" ## createNewSessionJni(): failure - inbound group session OOM");
        errorMessage = "inbound group session OOM";
    }
    else if (!aSessionKeyBuffer)
    {
        LOGE(" ## createNewSessionJni(): failure - invalid aSessionKey");
        errorMessage = "invalid aSessionKey";
    }
    else if (!(sessionKeyPtr = (*env)->GetByteArrayElements(env, aSessionKeyBuffer, &sessionWasCopied)))
    {
        LOGE(" ## createNewSessionJni(): failure - session key JNI allocation OOM");
        errorMessage = "Session key JNI allocation OOM";
    }
    else
    {
        sessionPtr = olm_inbound_group_session(sessionPtr);

        size_t sessionKeyLength = (size_t)(*env)->GetArrayLength(env, aSessionKeyBuffer);
        LOGD(" ## createNewSessionJni(): sessionKeyLength=%lu", (long unsigned int)(sessionKeyLength));

        size_t sessionResult;

        if (JNI_FALSE == isImported)
        {
            LOGD(" ## createNewSessionJni(): init");
            sessionResult = olm_init_inbound_group_session(sessionPtr, (const uint8_t*)sessionKeyPtr, sessionKeyLength);
        }
        else
        {
            LOGD(" ## createNewSessionJni(): import");
            sessionResult = olm_import_inbound_group_session(sessionPtr, (const uint8_t*)sessionKeyPtr, sessionKeyLength);
        }

        if (sessionResult == olm_error())
        {
            errorMessage = olm_inbound_group_session_last_error(sessionPtr);
            LOGE(" ## createNewSessionJni(): failure - init inbound session creation Msg=%s", errorMessage);
        }
        else
        {
            LOGD(" ## createNewSessionJni(): success - result=%lu", (long unsigned int)(sessionResult));
        }
    }

    if (sessionKeyPtr)
    {
        if (sessionWasCopied) {
            memset(sessionKeyPtr, 0, (size_t)(*env)->GetArrayLength(env, aSessionKeyBuffer));
        }
        (*env)->ReleaseByteArrayElements(env, aSessionKeyBuffer, sessionKeyPtr, JNI_ABORT);
    }

    if (errorMessage)
    {
        // release the allocated session
        if (sessionPtr)
        {
            olm_clear_inbound_group_session(sessionPtr);
            free(sessionPtr);
            sessionPtr = NULL;
        }
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), errorMessage);
    }

    return (jlong)(intptr_t)sessionPtr;
}

/**
 * Get a base64-encoded identifier for this inbound group session.
 * An exception is thrown if the operation fails.
 * @return the base64-encoded identifier
 */
JNIEXPORT jbyteArray OLM_INBOUND_GROUP_SESSION_FUNC_DEF(sessionIdentifierJni)(JNIEnv *env, jobject thiz)
{
    const char* errorMessage = NULL;
    OlmInboundGroupSession *sessionPtr = getInboundGroupSessionInstanceId(env, thiz);
    jbyteArray returnValue = 0;

    LOGD("## sessionIdentifierJni(): inbound group session IN");

    if (!sessionPtr)
    {
        LOGE(" ## sessionIdentifierJni(): failure - invalid inbound group session instance");
        errorMessage = "invalid inbound group session instance";
    }
    else
    {
        // get the size to alloc
        size_t lengthSessionId = olm_inbound_group_session_id_length(sessionPtr);
        LOGD(" ## sessionIdentifierJni(): inbound group session lengthSessionId=%lu",(long unsigned int)(lengthSessionId));

        uint8_t *sessionIdPtr = (uint8_t*)malloc(lengthSessionId*sizeof(uint8_t));

        if (!sessionIdPtr)
        {
            LOGE(" ## sessionIdentifierJni(): failure - inbound group session identifier allocation OOM");
            errorMessage = "inbound group session identifier allocation OOM";
        }
        else
        {
            size_t result = olm_inbound_group_session_id(sessionPtr, sessionIdPtr, lengthSessionId);

            if (result == olm_error())
            {
                errorMessage = (const char *)olm_inbound_group_session_last_error(sessionPtr);
                LOGE(" ## sessionIdentifierJni(): failure - get inbound group session identifier failure Msg=%s",(const char *)olm_inbound_group_session_last_error(sessionPtr));
            }
            else
            {
                LOGD(" ## sessionIdentifierJni(): success - inbound group session result=%lu sessionId=%.*s",(long unsigned int)(result), (int)(result), (char*)sessionIdPtr);

                returnValue = (*env)->NewByteArray(env, result);
                (*env)->SetByteArrayRegion(env, returnValue, 0 , result, (jbyte*)sessionIdPtr);
            }

            free(sessionIdPtr);
        }
    }

    if (errorMessage)
    {
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), errorMessage);
    }

    return returnValue;
}

/**
 * Decrypt a message.
 * An exception is thrown if the operation fails.
 * @param aEncryptedMsg the encrypted message
 * @param aDecryptMessageResult the decryptMessage information
 * @return the decrypted message
 */
JNIEXPORT jbyteArray OLM_INBOUND_GROUP_SESSION_FUNC_DEF(decryptMessageJni)(JNIEnv *env, jobject thiz, jbyteArray aEncryptedMsgBuffer, jobject aDecryptionResult)
{
    jbyteArray decryptedMsgBuffer = 0;
    const char* errorMessage = NULL;

    OlmInboundGroupSession *sessionPtr = getInboundGroupSessionInstanceId(env, thiz);
    jbyte *encryptedMsgPtr = NULL;
    jclass indexObjJClass = 0;
    jfieldID indexMsgFieldId;

    LOGD("## decryptMessageJni(): inbound group session IN");

    if (!sessionPtr)
    {
        LOGE(" ## decryptMessageJni(): failure - invalid inbound group session ptr=NULL");
        errorMessage = "invalid inbound group session ptr=NULL";
    }
    else if (!aEncryptedMsgBuffer)
    {
        LOGE(" ## decryptMessageJni(): failure - invalid encrypted message");
        errorMessage = "invalid encrypted message";
    }
    else if (!aDecryptionResult)
    {
        LOGE(" ## decryptMessageJni(): failure - invalid index object");
        errorMessage = "invalid index object";
    }
    else if (!(encryptedMsgPtr = (*env)->GetByteArrayElements(env, aEncryptedMsgBuffer, 0)))
    {
        LOGE(" ## decryptMessageJni(): failure - encrypted message JNI allocation OOM");
        errorMessage = "encrypted message JNI allocation OOM";
    }
    else if (!(indexObjJClass = (*env)->GetObjectClass(env, aDecryptionResult)))
    {
        LOGE("## decryptMessageJni(): failure - unable to get index class");
        errorMessage = "unable to get index class";
    }
    else if (!(indexMsgFieldId = (*env)->GetFieldID(env, indexObjJClass,"mIndex","J")))
    {
        LOGE("## decryptMessageJni(): failure - unable to get index type field");
        errorMessage = "unable to get index type field";
    }
    else
    {
        // get encrypted message length
        size_t encryptedMsgLength = (size_t)(*env)->GetArrayLength(env, aEncryptedMsgBuffer);
        uint8_t *tempEncryptedPtr = (uint8_t*)(malloc(encryptedMsgLength*sizeof(uint8_t)));

        // create a dedicated temp buffer to be used in next Olm API calls
        if (!tempEncryptedPtr)
        {
            LOGE(" ## decryptMessageJni(): failure - tempEncryptedPtr allocation OOM");
            errorMessage = "tempEncryptedPtr allocation OOM";
        }
        else
        {
            memcpy(tempEncryptedPtr, encryptedMsgPtr, encryptedMsgLength);
            LOGD(" ## decryptMessageJni(): encryptedMsgLength=%lu encryptedMsg=%.*s",(long unsigned int)(encryptedMsgLength), (int)(encryptedMsgLength), encryptedMsgPtr);

            // get max plaintext length
            size_t maxPlainTextLength = olm_group_decrypt_max_plaintext_length(sessionPtr,
                                                                               tempEncryptedPtr,
                                                                               encryptedMsgLength);
            if (maxPlainTextLength == olm_error())
            {
                errorMessage = olm_inbound_group_session_last_error(sessionPtr);
                LOGE(" ## decryptMessageJni(): failure - olm_group_decrypt_max_plaintext_length Msg=%s", errorMessage);
            }
            else
            {
                LOGD(" ## decryptMessageJni(): maxPlaintextLength=%lu",(long unsigned int)(maxPlainTextLength));

                uint32_t messageIndex = 0;

                // allocate output decrypted message
                uint8_t *plainTextMsgPtr = (uint8_t*)(malloc(maxPlainTextLength*sizeof(uint8_t)));

                if (!plainTextMsgPtr)
                {
                    LOGE(" ## decryptMessageJni(): failure - plainTextMsgPtr allocation OOM");
                    errorMessage = "plainTextMsgPtr allocation OOM";
                }
                else
                {
                // decrypt, but before reload encrypted buffer (previous one was destroyed)
                memcpy(tempEncryptedPtr, encryptedMsgPtr, encryptedMsgLength);
                size_t plaintextLength = olm_group_decrypt(sessionPtr,
                                                           tempEncryptedPtr,
                                                           encryptedMsgLength,
                                                           plainTextMsgPtr,
                                                           maxPlainTextLength,
                                                           &messageIndex);
                if (plaintextLength == olm_error())
                {
                    errorMessage = olm_inbound_group_session_last_error(sessionPtr);
                    LOGE(" ## decryptMessageJni(): failure - olm_group_decrypt Msg=%s", errorMessage);
                }
                else
                {
                    // update index
                    (*env)->SetLongField(env, aDecryptionResult, indexMsgFieldId, (jlong)messageIndex);

                    decryptedMsgBuffer = (*env)->NewByteArray(env, plaintextLength);
                    (*env)->SetByteArrayRegion(env, decryptedMsgBuffer, 0 , plaintextLength, (jbyte*)plainTextMsgPtr);

                    LOGD(" ## decryptMessageJni(): UTF-8 Conversion - decrypted returnedLg=%lu OK",(long unsigned int)(plaintextLength));
                }

                memset(plainTextMsgPtr, 0, maxPlainTextLength*sizeof(uint8_t));
                free(plainTextMsgPtr);
                }
            }

            if (tempEncryptedPtr)
            {
                free(tempEncryptedPtr);
            }
        }
    }

    // free alloc
    if (encryptedMsgPtr)
    {
        (*env)->ReleaseByteArrayElements(env, aEncryptedMsgBuffer, encryptedMsgPtr, JNI_ABORT);
    }

    if (errorMessage)
    {
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), errorMessage);
    }

    return decryptedMsgBuffer;
}

/**
 * Provides the first known index.
 * An exception is thrown if the operation fails.
 * @return the first known index
 */
JNIEXPORT jlong OLM_INBOUND_GROUP_SESSION_FUNC_DEF(firstKnownIndexJni)(JNIEnv *env, jobject thiz)
{
    const char* errorMessage = NULL;
    OlmInboundGroupSession *sessionPtr = getInboundGroupSessionInstanceId(env, thiz);
    long returnValue = 0;

    LOGD("## firstKnownIndexJni(): inbound group session IN");

    if (!sessionPtr)
    {
        LOGE(" ## firstKnownIndexJni(): failure - invalid inbound group session instance");
        errorMessage = "invalid inbound group session instance";
    }
    else
    {
        returnValue = olm_inbound_group_session_first_known_index(sessionPtr);
    }

    if (errorMessage)
    {
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), errorMessage);
    }

    return returnValue;
}

/**
 * Tells if the session is verified.
 * An exception is thrown if the operation fails.
 * @return true if the session is verified
 */
JNIEXPORT jboolean OLM_INBOUND_GROUP_SESSION_FUNC_DEF(isVerifiedJni)(JNIEnv *env, jobject thiz)
{
    const char* errorMessage = NULL;
    OlmInboundGroupSession *sessionPtr = getInboundGroupSessionInstanceId(env, thiz);
    jboolean returnValue = JNI_FALSE;

    LOGD("## isVerifiedJni(): inbound group session IN");

    if (!sessionPtr)
    {
        LOGE(" ## isVerifiedJni(): failure - invalid inbound group session instance");
        errorMessage = "invalid inbound group session instance";
    }
    else
    {
        LOGE(" ## isVerifiedJni(): faaa %d", olm_inbound_group_session_is_verified(sessionPtr));

        returnValue = (0 != olm_inbound_group_session_is_verified(sessionPtr)) ? JNI_TRUE : JNI_FALSE;
    }

    if (errorMessage)
    {
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), errorMessage);
    }

    return returnValue;
}

/**
 * Exports the session as byte array from a message index
 * An exception is thrown if the operation fails.
 * @param messageIndex key used to encrypt the serialized session data
 * @return the session saved as bytes array
 **/
JNIEXPORT jbyteArray OLM_INBOUND_GROUP_SESSION_FUNC_DEF(exportJni)(JNIEnv *env, jobject thiz, jlong messageIndex) {
    jbyteArray exportedByteArray = 0;
    const char* errorMessage = NULL;
    OlmInboundGroupSession *sessionPtr = getInboundGroupSessionInstanceId(env, thiz);

    LOGD("## exportJni(): inbound group session IN");

    if (!sessionPtr)
    {
        LOGE(" ## exportJni (): failure - invalid inbound group session instance");
        errorMessage = "invalid inbound group session instance";
    }
    else
    {
        size_t length = olm_export_inbound_group_session_length(sessionPtr);

        LOGD(" ## exportJni(): length =%lu", (long unsigned int)(length));

        void *bufferPtr = malloc(length * sizeof(uint8_t));

        if (!bufferPtr)
        {
            LOGE(" ## exportJni(): failure - pickledPtr buffer OOM");
            errorMessage = "pickledPtr buffer OOM";
        }
        else
        {
           size_t result = olm_export_inbound_group_session(sessionPtr,
                                                            (uint8_t*)bufferPtr,
                                                            length,
                                                            (long) messageIndex);

           if (result == olm_error())
           {
               errorMessage = olm_inbound_group_session_last_error(sessionPtr);
               LOGE(" ## exportJni(): failure - olm_export_inbound_group_session() Msg=%s", errorMessage);
           }
           else
           {
               LOGD(" ## exportJni(): success - result=%lu buffer=%.*s", (long unsigned int)(result), (int)(length), (char*)(bufferPtr));

               exportedByteArray = (*env)->NewByteArray(env, length);
               (*env)->SetByteArrayRegion(env, exportedByteArray, 0 , length, (jbyte*)bufferPtr);

               // clean before leaving
               memset(bufferPtr, 0, length);
           }

           free(bufferPtr);
        }
    }

    if (errorMessage)
    {
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), errorMessage);
    }

    return exportedByteArray;
}

/**
 * Serialize and encrypt session instance into a base64 string.<br>
 * An exception is thrown if the operation fails.
 * @param aKeyBuffer key used to encrypt the serialized session data
 * @return a base64 string if operation succeed, null otherwise
 **/
JNIEXPORT jbyteArray OLM_INBOUND_GROUP_SESSION_FUNC_DEF(serializeJni)(JNIEnv *env, jobject thiz, jbyteArray aKeyBuffer)
{
    const char* errorMessage = NULL;

    jbyteArray pickledDataRet = 0;
    jbyte* keyPtr = NULL;
    jboolean keyWasCopied = JNI_FALSE;
    OlmInboundGroupSession* sessionPtr = getInboundGroupSessionInstanceId(env, thiz);

    LOGD("## inbound group session serializeJni(): IN");

    if (!sessionPtr)
    {
        LOGE(" ## serializeJni(): failure - invalid session ptr");
        errorMessage = "invalid session ptr";
    }
    else if (!aKeyBuffer)
    {
        LOGE(" ## serializeJni(): failure - invalid key");
        errorMessage = "invalid key";
    }
    else if (!(keyPtr = (*env)->GetByteArrayElements(env, aKeyBuffer, &keyWasCopied)))
    {
        LOGE(" ## serializeJni(): failure - keyPtr JNI allocation OOM");
        errorMessage = "keyPtr JNI allocation OOM";
    }
    else
    {
        size_t pickledLength = olm_pickle_inbound_group_session_length(sessionPtr);
        size_t keyLength = (size_t)(*env)->GetArrayLength(env, aKeyBuffer);
        LOGD(" ## serializeJni(): pickledLength=%lu keyLength=%lu", (long unsigned int)(pickledLength), (long unsigned int)(keyLength));

        void *pickledPtr = malloc(pickledLength*sizeof(uint8_t));

        if (!pickledPtr)
        {
            LOGE(" ## serializeJni(): failure - pickledPtr buffer OOM");
            errorMessage = "pickledPtr buffer OOM";
        }
        else
        {
            size_t result = olm_pickle_inbound_group_session(sessionPtr,
                                                             (void const *)keyPtr,
                                                              keyLength,
                                                              (void*)pickledPtr,
                                                              pickledLength);
            if (result == olm_error())
            {
                errorMessage = olm_inbound_group_session_last_error(sessionPtr);
                LOGE(" ## serializeJni(): failure - olm_pickle_outbound_group_session() Msg=%s", errorMessage);
            }
            else
            {
                LOGD(" ## serializeJni(): success - result=%lu pickled=%.*s", (long unsigned int)(result), (int)(pickledLength), (char*)(pickledPtr));

                pickledDataRet = (*env)->NewByteArray(env, pickledLength);
                (*env)->SetByteArrayRegion(env, pickledDataRet, 0 , pickledLength, (jbyte*)pickledPtr);
            }

            free(pickledPtr);
        }
    }

    // free alloc
    if (keyPtr)
    {
        if (keyWasCopied) {
            memset(keyPtr, 0, (size_t)(*env)->GetArrayLength(env, aKeyBuffer));
        }
        (*env)->ReleaseByteArrayElements(env, aKeyBuffer, keyPtr, JNI_ABORT);
    }

    if (errorMessage)
    {
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), errorMessage);
    }

    return pickledDataRet;
}

/**
 * Allocate a new session and initialize it with the serialisation data.<br>
 * An exception is thrown if the operation fails.
 * @param aSerializedData the session serialisation buffer
 * @param aKey the key used to encrypt the serialized account data
 * @return the deserialized session
 **/
JNIEXPORT jlong OLM_INBOUND_GROUP_SESSION_FUNC_DEF(deserializeJni)(JNIEnv *env, jobject thiz, jbyteArray aSerializedDataBuffer, jbyteArray aKeyBuffer)
{
    const char* errorMessage = NULL;

    OlmInboundGroupSession* sessionPtr = NULL;
    size_t sessionSize = olm_inbound_group_session_size();
    jbyte* keyPtr = NULL;
    jboolean keyWasCopied = JNI_FALSE;
    jbyte* pickledPtr = NULL;

    LOGD("## deserializeJni(): IN");

    if (!sessionSize)
    {
        LOGE(" ## deserializeJni(): failure - inbound group session size = 0");
        errorMessage = "inbound group session size = 0";
    }
    else if (!(sessionPtr = (OlmInboundGroupSession*)malloc(sessionSize)))
    {
        LOGE(" ## deserializeJni(): failure - session failure OOM");
        errorMessage = "session failure OOM";
    }
    else if (!aKeyBuffer)
    {
        LOGE(" ## deserializeJni(): failure - invalid key");
        errorMessage = "invalid key";
    }
    else if (!aSerializedDataBuffer)
    {
        LOGE(" ## deserializeJni(): failure - serialized data");
        errorMessage = "serialized data";
    }
    else if (!(keyPtr = (*env)->GetByteArrayElements(env, aKeyBuffer, &keyWasCopied)))
    {
        LOGE(" ## deserializeJni(): failure - keyPtr JNI allocation OOM");
        errorMessage = "keyPtr JNI allocation OOM";
    }
    else if (!(pickledPtr = (*env)->GetByteArrayElements(env, aSerializedDataBuffer, 0)))
    {
        LOGE(" ## deserializeJni(): failure - pickledPtr JNI allocation OOM");
        errorMessage = "pickledPtr JNI allocation OOM";
    }
    else
    {
        sessionPtr = olm_inbound_group_session(sessionPtr);

        size_t pickledLength = (size_t)(*env)->GetArrayLength(env, aSerializedDataBuffer);
        size_t keyLength = (size_t)(*env)->GetArrayLength(env, aKeyBuffer);
        LOGD(" ## deserializeJni(): pickledLength=%lu keyLength=%lu",(long unsigned int)(pickledLength), (long unsigned int)(keyLength));
        LOGD(" ## deserializeJni(): pickled=%.*s", (int)(pickledLength), (char const *)pickledPtr);

        size_t result = olm_unpickle_inbound_group_session(sessionPtr,
                                                           (void const *)keyPtr,
                                                           keyLength,
                                                           (void*)pickledPtr,
                                                           pickledLength);
        if (result == olm_error())
        {
            errorMessage = olm_inbound_group_session_last_error(sessionPtr);
            LOGE(" ## deserializeJni(): failure - olm_unpickle_inbound_group_session() Msg=%s", errorMessage);
        }
        else
        {
            LOGD(" ## deserializeJni(): success - result=%lu ", (long unsigned int)(result));
        }
    }

    // free alloc
    if (keyPtr)
    {
        if (keyWasCopied) {
            memset(keyPtr, 0, (size_t)(*env)->GetArrayLength(env, aKeyBuffer));
        }
        (*env)->ReleaseByteArrayElements(env, aKeyBuffer, keyPtr, JNI_ABORT);
    }

    if (pickledPtr)
    {
        (*env)->ReleaseByteArrayElements(env, aSerializedDataBuffer, pickledPtr, JNI_ABORT);
    }

    if (errorMessage)
    {
        if (sessionPtr)
        {
            olm_clear_inbound_group_session(sessionPtr);
            free(sessionPtr);
            sessionPtr = NULL;
        }
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"), errorMessage);
    }

    return (jlong)(intptr_t)sessionPtr;
}
