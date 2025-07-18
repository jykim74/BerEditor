#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define XMLSEC_NO_XSLT
#define XMLSEC_CRYPTO_OPENSSL

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/crypto.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

/*
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/x509.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/openssl/symbols.h>
#include <xmlsec/openssl/keysstore.h>
#include <xmlsec/transforms.h>
*/

#include "js_pki_xml.h"



void JS_XML_init()
{
#ifndef XMLSEC_NO_XSLT
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
        xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
#endif /* XMLSEC_NO_XSLT */

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
    /* disable everything */
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        return;
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        return;
    }


    /* Init crypto library */
    if(xmlSecOpenSSLAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        return;
    }

    /* Init xmlsec-crypto library */
    if(xmlSecOpenSSLInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return;
    }
}

void JS_XML_final()
{
    /* Shutdown xmlsec-crypto library */
    xmlSecOpenSSLShutdown();

    /* Shutdown crypto library */
    xmlSecOpenSSLAppShutdown();

    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();
}


int JS_XML_signWithInfo( const char *pSrcFile, const char* pPriKeyPath, const char *pDstFile )
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    if( pSrcFile == NULL || pPriKeyPath == NULL || pDstFile == NULL )
        return -1;

    /* load template */
    doc = xmlReadFile(pSrcFile, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", pSrcFile);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", pSrcFile);
        goto done;
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecOpenSSLAppKeyLoadEx(pPriKeyPath, xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", pPriKeyPath);
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, BAD_CAST pPriKeyPath) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", pPriKeyPath);
        goto done;
    }

    /* sign the template */
    if(xmlSecDSigCtxSign(dsigCtx, node) < 0) {
        fprintf(stderr,"Error: signature failed\n");
        goto done;
    }

    xmlSaveFormatFileEnc( pDstFile, doc, "UTF-8", 1 );

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }

    return(res);
}

int JS_XML_signDoc( const char *pSrcFile, const char* pPriKeyPath, const char *pDstFile )
{
    xmlDocPtr doc = NULL;
    xmlNodePtr signNode = NULL;
    xmlNodePtr refNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    if( pSrcFile == NULL || pPriKeyPath == NULL || pDstFile == NULL )
        return -1;


    /* load doc file */
    doc = xmlReadFile(pSrcFile, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", pSrcFile);
        goto done;
    }

    /* create signature template for RSA-SHA1 enveloped signature */
    signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
                                         xmlSecTransformRsaSha1Id, NULL);
    if(signNode == NULL) {
        fprintf(stderr, "Error: failed to create signature template\n");
        goto done;
    }

    /* add <dsig:Signature/> node to the doc */
    xmlAddChild(xmlDocGetRootElement(doc), signNode);

    /* add reference */
    refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformSha1Id,
                                              NULL, BAD_CAST "", NULL);
    if(refNode == NULL) {
        fprintf(stderr, "Error: failed to add reference to signature template\n");
        goto done;
    }

    /* add enveloped transform */
    if(xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
        fprintf(stderr, "Error: failed to add enveloped transform to reference\n");
        goto done;
    }

    /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed document */
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
        fprintf(stderr, "Error: failed to add key info\n");
        goto done;
    }

    if(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
        fprintf(stderr, "Error: failed to add key name\n");
        goto done;
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecOpenSSLAppKeyLoadEx(pPriKeyPath, xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", pPriKeyPath);
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, BAD_CAST pPriKeyPath) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", pPriKeyPath);
        goto done;
    }

    /* sign the template */
    if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
        fprintf(stderr,"Error: signature failed\n");
        goto done;
    }

    /* print signed document to stdout */
    //xmlDocDump(stdout, doc);

    xmlSaveFormatFileEnc( pDstFile, doc, "UTF-8", 1 );

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
    return(res);
}

/**
 * verify_signature_results:
 * @dsigCtx:            the XMLDSig context
 *
 * Verifies XML signature results to ensure that signature was applied
 * to the expected data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
static int verify_signature_results(xmlSecDSigCtxPtr dsigCtx) {
    xmlSecDSigReferenceCtxPtr dsigRefCtx;
    xmlSecTransformPtr transform;

    /* check that signature verification succeeded */
    if(dsigCtx->status != xmlSecDSigStatusSucceeded) {
        fprintf(stderr,"Error: Signature verificaton result is not SUCCESS\n");
        return(-1);
    }

    /* in this example we expect exactly ONE reference with URI="" and
    *  exactly ONE enveloped signature transform (i.e. the whole document is signed)*/
    if(xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences)) != 1) {
        fprintf(stderr,"Error: Exactly one Reference is expected\n");
        return(-1);
    }
    dsigRefCtx = (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), 0);
    if((dsigRefCtx == NULL) || (dsigRefCtx->status != xmlSecDSigStatusSucceeded)) {
        fprintf(stderr,"Error: Reference verification result is not SUCCESS\n");
        return(-1);
    }

    /* check URI */
    if(!xmlStrEqual(dsigRefCtx->uri, BAD_CAST "")) {
        fprintf(stderr,"Error: Reference URI value doesn't match expected one\n");
        return(-1);
    }

    /* check transforms: we expect only one "enveloped signature" transform */
    transform = dsigRefCtx->transformCtx.first;
    if((transform == NULL) || (!xmlStrEqual(transform->id->name, xmlSecNameEnveloped))) {
        fprintf(stderr,"Error: First Transform name '%s' doesn't match expected '%s'\n", (transform != NULL ? transform->id->name : BAD_CAST "NULL"), xmlSecNameEnveloped);
        return(-1);
    }

    /* all other transforms should be inserted by XMLSec */
    transform = transform->next;
    while(transform != NULL) {
        if((transform->flags & XMLSEC_TRANSFORM_FLAGS_USER_SPECIFIED) != 0) {
            fprintf(stderr,"Error: Found unexpected Transform name '%s'\n", transform->id->name);
            return(-1);
        }
        transform = transform->next;
    }

    /* all good! */
    return(0);
}

/**
 * verify_file:
 * @xml_file:           the signed XML file name.
 * @key_file:           the PEM public key file name.
 *
 * Verifies XML signature in #xml_file using public key from #key_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */

int JS_XML_verify( const char* pSrcFile, const char* pPubKeyPath )
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    /* load file */
    doc = xmlReadFile(pSrcFile, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", pSrcFile);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", pSrcFile);
        goto done;
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load public key */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadEx(pPubKeyPath, xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load public pem key from \"%s\"\n", pPubKeyPath);
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, BAD_CAST pPubKeyPath) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", pPubKeyPath);
        goto done;
    }

    /* Verify signature */
    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        fprintf(stderr,"Error: signature verificaton failed\n");
        goto done;
    }

    /* verif results and print outcome to stdout */
    if(verify_signature_results(dsigCtx) == 0) {
        fprintf(stdout, "Signature is OK\n");
    } else {
        fprintf(stdout, "Signature is INVALID\n");
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
    return(res);
}

/**
 * encrypt_file:
 * @tmpl_file:          the encryption template file name.
 * @key_file:           the Triple DES key file.
 * @data:               the binary data to encrypt.
 * @dataSize:           the binary data size.
 *
 * Encrypts binary #data using template from #tmpl_file and DES key from
 * #key_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */

int JS_XML_encryptWithInfo( const char* pSrcFile, const BIN *pKey, const BIN *pData, const char *pDstFile )
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;

    xmlSecBufferPtr key;

    assert(pSrcFile);
    assert(pKey);
    assert(pData);
    assert( pDstFile );

    /* load template */
    doc = xmlReadFile(pSrcFile, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", pSrcFile);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", pSrcFile);
        goto done;
    }

    /* create encryption context, we don't need keys manager in this example */
    encCtx = xmlSecEncCtxCreate(NULL);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
        goto done;
    }

    /* load DES key, assuming that there is not password */

    if( xmlSecBufferInitialize( key, 0 ) < 0 )
    {
        fprintf( stderr, "Buffer init failed\n" );
        goto done;
    }

    if( xmlSecBufferSetData( key, pKey->pVal, pKey->nLen ) < 0 )
    {
        fprintf( stderr, "Buffer set key failed\n" );
        goto done;
    }

    encCtx->encKey = xmlSecKeyReadBuffer( xmlSecKeyDataDesId, key );
    if(encCtx->encKey == NULL) {
        fprintf(stderr,"Error: failed to load des key from buffer\n");
        goto done;
    }
/*
    encCtx->encKey = xmlSecKeyReadBinaryFile(xmlSecKeyDataDesId, key_file);
    if(encCtx->encKey == NULL) {
        fprintf(stderr,"Error: failed to load des key from binary file \"%s\"\n", key_file);
        goto done;
    }
*/
    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(encCtx->encKey, BAD_CAST "key_file") < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", "key_file");
        goto done;
    }

    /* encrypt the data */
    if(xmlSecEncCtxBinaryEncrypt(encCtx, node, pData->pVal, pData->nLen) < 0) {
        fprintf(stderr,"Error: encryption failed\n");
        goto done;
    }

    /* print encrypted data with document to stdout */
    // xmlDocDump(stdout, doc);
    xmlSaveFormatFileEnc( pDstFile, doc, "UTF-8", 1 );

    /* success */
    res = 0;

done:

    /* cleanup */
    if(encCtx != NULL) {
        xmlSecEncCtxDestroy(encCtx);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }

    if( key != NULL )
    {
        xmlSecBufferFinalize( key );
    }

    return(res);
}

/**
 * encrypt_file:
 * @xml_file:           the encryption template file name.
 * @key_file:           the Triple DES key file.
 *
 * Encrypts #xml_file using a dynamicaly created template and DES key from
 * #key_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */


int JS_XML_encrypt( const char* pSrcFile, const BIN *pKey, const char *pDstFile )
{
    xmlDocPtr doc = NULL;
    xmlNodePtr encDataNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;
    xmlSecBufferPtr key;

    assert(pSrcFile);
    assert(pKey);
    assert(pDstFile);

    /* load template */
    doc = xmlReadFile(pSrcFile, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", pSrcFile);
        goto done;
    }

    /* create encryption template to encrypt XML file and replace
     * its content with encryption result */
    encDataNode = xmlSecTmplEncDataCreate(doc, xmlSecTransformDes3CbcId,
                                          NULL, xmlSecTypeEncElement, NULL, NULL);
    if(encDataNode == NULL) {
        fprintf(stderr, "Error: failed to create encryption template\n");
        goto done;
    }

    /* we want to put encrypted data in the <enc:CipherValue/> node */
    if(xmlSecTmplEncDataEnsureCipherValue(encDataNode) == NULL) {
        fprintf(stderr, "Error: failed to add CipherValue node\n");
        goto done;
    }

    /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed document */
    keyInfoNode = xmlSecTmplEncDataEnsureKeyInfo(encDataNode, NULL);
    if(keyInfoNode == NULL) {
        fprintf(stderr, "Error: failed to add key info\n");
        goto done;
    }

    if(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
        fprintf(stderr, "Error: failed to add key name\n");
        goto done;
    }

    /* create encryption context, we don't need keys manager in this example */
    encCtx = xmlSecEncCtxCreate(NULL);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
        goto done;
    }

    /* load DES key, assuming that there is not password */
    if( xmlSecBufferInitialize( key, 0 ) < 0 )
    {
        fprintf( stderr, "Buffer init failed\n" );
        goto done;
    }

    if( xmlSecBufferSetData( key, pKey->pVal, pKey->nLen ) < 0 )
    {
        fprintf( stderr, "Buffer set key failed\n" );
        goto done;
    }

    encCtx->encKey = xmlSecKeyReadBuffer( xmlSecKeyDataDesId, key );
    if(encCtx->encKey == NULL) {
        fprintf(stderr,"Error: failed to load des key from buffer\n");
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(encCtx->encKey, BAD_CAST "key_file") < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", "key_file");
        goto done;
    }

    /* encrypt the data */
    if(xmlSecEncCtxXmlEncrypt(encCtx, encDataNode, xmlDocGetRootElement(doc)) < 0) {
        fprintf(stderr,"Error: encryption failed\n");
        goto done;
    }

    /* we template is inserted in the doc */
    encDataNode = NULL;

    /* print encrypted data with document to stdout */
    //xmlDocDump(stdout, doc);
    xmlSaveFormatFileEnc( pDstFile, doc, "UTF-8", 1 );

    /* success */
    res = 0;

done:

    /* cleanup */
    if(encCtx != NULL) {
        xmlSecEncCtxDestroy(encCtx);
    }

    if(encDataNode != NULL) {
        xmlFreeNode(encDataNode);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }

    if( key != NULL )
    {
        xmlSecBufferFinalize( key );
    }

    return(res);
}

/**
 * decrypt_file:
 * @enc_file:           the encrypted XML  file name.
 * @key_file:           the Triple DES key file.
 *
 * Decrypts the XML file #enc_file using DES key from #key_file and
 * prints results to stdout.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */

int JS_XML_decrypt(const char* pSrcFile, const BIN *pKey, const char *pDstFile )
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;
    xmlSecBufferPtr key;

    assert(pSrcFile);
    assert(pKey);
    assert(pDstFile);

    /* load template */
    doc = xmlReadFile(pSrcFile, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", pSrcFile);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", pSrcFile);
        goto done;
    }

    /* create encryption context, we don't need keys manager in this example */
    encCtx = xmlSecEncCtxCreate(NULL);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
        goto done;
    }

    /* load DES key */
    if( xmlSecBufferInitialize( key, 0 ) < 0 )
    {
        fprintf( stderr, "Buffer init failed\n" );
        goto done;
    }

    if( xmlSecBufferSetData( key, pKey->pVal, pKey->nLen ) < 0 )
    {
        fprintf( stderr, "Buffer set key failed\n" );
        goto done;
    }

    encCtx->encKey = xmlSecKeyReadBuffer( xmlSecKeyDataDesId, key );
    if(encCtx->encKey == NULL) {
        fprintf(stderr,"Error: failed to load des key from buffer\n");
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(encCtx->encKey, BAD_CAST "key_file") < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", "key_file");
        goto done;
    }

    /* decrypt the data */
    if((xmlSecEncCtxDecrypt(encCtx, node) < 0) || (encCtx->result == NULL)) {
        fprintf(stderr,"Error: decryption failed\n");
        goto done;
    }

    /* print decrypted data to stdout */
    if(encCtx->resultReplaced != 0) {
        fprintf(stdout, "Decrypted XML data:\n");
        //xmlDocDump(stdout, doc);
        xmlSaveFormatFileEnc( pDstFile, doc, "UTF-8", 1 );
    } else {
        fprintf(stdout, "Decrypted binary data (" XMLSEC_SIZE_FMT " bytes):\n",
                xmlSecBufferGetSize(encCtx->result));
        if(xmlSecBufferGetData(encCtx->result) != NULL) {
            fwrite(xmlSecBufferGetData(encCtx->result),
                   1,
                   xmlSecBufferGetSize(encCtx->result),
                   stdout);
        }
    }
    fprintf(stdout, "\n");

    /* success */
    res = 0;

done:
    /* cleanup */
    if(encCtx != NULL) {
        xmlSecEncCtxDestroy(encCtx);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }

    if( key != NULL )
    {
        xmlSecBufferFinalize( key );
    }

    return(res);
}
