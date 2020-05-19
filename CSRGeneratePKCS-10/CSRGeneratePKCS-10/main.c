//
//  main.c
//  CSRGeneratePKCS-10
//
//  Created by 野尽 on 2020/5/19.
//  Copyright © 2020 野尽. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#pragma comment(lib, "libeay32.lib")

/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
X509_NAME *parse_name(char *subject, long chtype, int multirdn)
{
    size_t buflen = strlen(subject)+1; /* to copy the types and values into. due to escaping, the copy can only become shorter */
    char *buf = OPENSSL_malloc(buflen);
    size_t max_ne = buflen / 2 + 1; /* maximum number of name elements */
    char **ne_types = OPENSSL_malloc(max_ne * sizeof (char *));
    char **ne_values = OPENSSL_malloc(max_ne * sizeof (char *));
    int *mval = OPENSSL_malloc (max_ne * sizeof (int));
    
    char *sp = subject, *bp = buf;
    int i, ne_num = 0;
    
    X509_NAME *n = NULL;
    int nid;
    
    if (!buf || !ne_types || !ne_values || !mval)
    {
        //BIO_printf(bio_err, "malloc error\n");
        goto error;
    }
    
    if (*subject != '/')
    {
        //BIO_printf(bio_err, "Subject does not start with '/'.\n");
        goto error;
    }
    sp++; /* skip leading / */
    
    /* no multivalued RDN by default */
    mval[ne_num] = 0;
    
    while (*sp)
    {
        /* collect type */
        ne_types[ne_num] = bp;
        while (*sp)
        {
            if (*sp == '\\') /* is there anything to escape in the type...? */
            {
                if (*++sp)
                    *bp++ = *sp++;
                else
                {
                    //BIO_printf(bio_err, "escape character at end of string\n");
                    goto error;
                }
            }
            else if (*sp == '=')
            {
                sp++;
                *bp++ = '\0';
                break;
            }
            else
                *bp++ = *sp++;
        }
        if (!*sp)
        {
            //BIO_printf(bio_err, "end of string encountered while processing type of subject name element #%d\n", ne_num);
            goto error;
        }
        ne_values[ne_num] = bp;
        while (*sp)
        {
            if (*sp == '\\')
            {
                if (*++sp)
                    *bp++ = *sp++;
                else
                {
                    //BIO_printf(bio_err, "escape character at end of string\n");
                    goto error;
                }
            }
            else if (*sp == '/')
            {
                sp++;
                /* no multivalued RDN by default */
                mval[ne_num+1] = 0;
                break;
            }
            else if (*sp == '+' && multirdn)
            {
                /* a not escaped + signals a mutlivalued RDN */
                sp++;
                mval[ne_num+1] = -1;
                break;
            }
            else
                *bp++ = *sp++;
        }
        *bp++ = '\0';
        ne_num++;
    }
    
    if (!(n = X509_NAME_new()))
        goto error;
    
    for (i = 0; i < ne_num; i++)
    {
        if ((nid=OBJ_txt2nid(ne_types[i])) == NID_undef)
        {
            //BIO_printf(bio_err, "Subject Attribute %s has no known NID, skipped\n", ne_types[i]);
            continue;
        }
        
        if (!*ne_values[i])
        {
            //BIO_printf(bio_err, "No value provided for Subject Attribute %s, skipped\n", ne_types[i]);
            continue;
        }
        
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype, (unsigned char*)ne_values[i], -1,-1,mval[i]))
            goto error;
    }
    
    OPENSSL_free(ne_values);
    OPENSSL_free(ne_types);
    OPENSSL_free(buf);
    OPENSSL_free(mval);
    return n;
    
error:
    X509_NAME_free(n);
    if (ne_values)
        OPENSSL_free(ne_values);
    if (ne_types)
        OPENSSL_free(ne_types);
    if (mval)
        OPENSSL_free(mval);
    if (buf)
        OPENSSL_free(buf);
    return NULL;
}

X509_NAME *CreateDN(char *pbEmail, char *pbCN, char *pbOU, char *pbO, char *pbL, char *pbST, char *pbC)
{
    X509_NAME *pX509Name = NULL;
    if(pbCN == NULL)
    {
        return NULL;
    }
    
    if (!(pX509Name = X509_NAME_new()))
    {
        return NULL;
    }
    //    X509_NAME_add_entry_by_txt(pX509Name, "emailAddress", V_ASN1_UTF8STRING, pbEmail, -1, -1, 0);
    X509_NAME_add_entry_by_txt(pX509Name, "CN", V_ASN1_UTF8STRING, pbCN, -1, -1, 0);
    //    X509_NAME_add_entry_by_txt(pX509Name, "OU", V_ASN1_UTF8STRING, pbOU, -1, -1, 0);
    X509_NAME_add_entry_by_txt(pX509Name, "O", V_ASN1_UTF8STRING, pbO, -1, -1, 0);
    //    X509_NAME_add_entry_by_txt(pX509Name, "L", V_ASN1_UTF8STRING, pbL, -1, -1, 0);
    //    X509_NAME_add_entry_by_txt(pX509Name, "ST", V_ASN1_UTF8STRING, pbST, -1, -1, 0);
    X509_NAME_add_entry_by_txt(pX509Name, "C", V_ASN1_UTF8STRING, pbC, -1, -1, 0);
    return pX509Name;
}

long int GenCSR(char *pbDN, int nDNLen, char *pCSR, size_t nCSRSize, char *privateKey)
{
    X509_REQ        *pX509Req = NULL;
    int                iRV = 0;
    long            lVer = 3;
    const X509_NAME        *pX509DN = NULL;
    EVP_PKEY        *pEVPKey = NULL;
    RSA                *pRSA = NULL;
    X509_NAME_ENTRY    *pX509Entry = NULL;
    char            szBuf[255] = {0};
    unsigned char            mdout[32];
    unsigned int                nLen, nModLen;
    int                bits = 2048;
    unsigned long    E = RSA_3;
    unsigned char    *pDer = NULL;
    unsigned char    *p = NULL;
    FILE            *fp = NULL;
    const EVP_MD    *md = NULL;
    X509            *pX509 = NULL;
    BIO                *pBIO = NULL;
    BIO                *pPemBIO = NULL;
    BUF_MEM            *pBMem = NULL;
    
    if(pbDN == NULL)
    {
        return -1;
    }
    
    // 用户信息
    pX509DN = parse_name(pbDN, V_ASN1_UTF8STRING, 0);
    
    // 创建请求对象
    pX509Req = X509_REQ_new();
    
    // 设置版本号
    iRV = X509_REQ_set_version(pX509Req, lVer);
    
    // 用户信息放入 subject pX509Name
    iRV = X509_REQ_set_subject_name(pX509Req, pX509DN);
    
    /* 向证书请求中添加 公钥 */
    // 创建公钥 EVP_PKEY 结构
    // EVP_PKEY用来存放非对称密钥信息，可以是 RSA、 DSA、 DH 或 ECC 密钥。其中， ptr 用来存放密钥结构地址， attributes 堆栈用来存放密钥属性。
    /*
     struct evp_pkey_st
     {
     int type;
     int save_type;
     int references;
     const EVP_PKEY_ASN1_METHOD *ameth;
     ENGINE *engine;
     union
     {
     void *ptr;
     # ifndef OPENSSL_NO_RSA
     struct rsa_st *rsa;      RSA
     # endif
     # ifndef OPENSSL_NO_DSA
     struct dsa_st *dsa;     DSA
     # endif
     # ifndef OPENSSL_NO_DH
     struct dh_st *dh;       DH
     # endif
     # ifndef OPENSSL_NO_EC
     struct ec_key_st *ec;   ECC
     # endif
     } pkey;
     int save_parameters;
     STACK_OF(X509_ATTRIBUTE) *attributes;  [0]
     CRYPTO_RWLOCK *lock;
     };
     */
    pEVPKey = EVP_PKEY_new();
    
    /* 产生 sm2 密钥对 */
    /* 构造 EC_KEY 数据结构 */
    EC_KEY *key;
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    BIGNUM *privkey;

    key = EC_KEY_new();
    if(key == NULL)
    {
        printf("EC_KEY_new err!\n");
        return -1;
    }

    /* 根据选择的椭圆曲线生成密钥参数 group */
    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if(group == NULL)
    {
        printf("EC_GROUP_new_by_curve_name err!\n");
        return -1;
    }

    /* 设置密钥参数 */
    int ret = EC_KEY_set_group(key, group);
    if(ret != 1)
    {
        printf("EC_KEY_set_group err.\n");
        return -1;
    }

    /* 生成密钥 */
    ret = EC_KEY_generate_key(key);
    if(ret != 1)
    {
        printf("EC_KEY_generate_key err.\n");
        return -1;
    }

    /* 检查密钥 */
    ret = EC_KEY_check_key(key);
    if(ret != 1)
    {
        printf("check key err.\n");
        return -1;
    }

    /* 获取 sm2 密钥，公私钥*/
    pubkey = EC_KEY_get0_public_key(key);
    privkey = EC_KEY_get0_private_key(key);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, pubkey, x, y, NULL);
    //    if (EC_POINT_get_affine_coordinates_GFp(group, pubkey, x, y, NULL))
    //    {
    //       BN_print_fp(stdout, x);
    //       putc('\n', stdout);
    //       BN_print_fp(stdout, y);
    //       putc('\n', stdout);
    //    }

    // 打印 sm2 公私钥
    printf("公钥：\n");
    char *X = BN_bn2hex(x);
    printf("X : %s\n", X);
    char *Y = BN_bn2hex(y);
    printf("Y : %s\n\n", Y);
    char *D = BN_bn2hex(privkey);
    privateKey = D;
    printf("私钥：\n");
    printf("D = %s\n\n", D);
    
//    // 将RSA对象pRSA赋给EVP_PKEY结构
//    EVP_PKEY_assign_RSA(pEVPKey, pRSA);
    
    // 将 sm2 密钥对赋给EVP_PKEY结构
//    EVP_PKEY_assign_EC_KEY(pEVPKey, key);
//    EVP_PKEY_assign(pEVPKey, EVP_PKEY_EC, key);
//    EVP_PKEY_assign(pEVPKey, EVP_PKEY_SM2, key);
    EVP_PKEY_set1_EC_KEY(pEVPKey, key);
    EVP_PKEY_set_alias_type(pEVPKey, EVP_PKEY_SM2);


    
    // 加入主体公钥 pEVPKey 到证书请求
    iRV = X509_REQ_set_pubkey(pX509Req, pEVPKey);
    
    /* attribute */
    char szBasicConstraints[] = "";
    strcpy(szBuf, szBasicConstraints);
    nLen = strlen(szBuf);
    iRV = X509_REQ_add1_attr_by_txt(pX509Req, "basicConstraints", V_ASN1_UTF8STRING, szBuf, nLen);
    
    char szKeyIdentifier[] = "";
    strcpy(szBuf, szKeyIdentifier);
    nLen = strlen(szBuf);
    iRV = X509_REQ_add1_attr_by_txt(pX509Req, "subjectKeyIdentifier", V_ASN1_UTF8STRING, szBuf, nLen);
    
    char szKeyUsage[] = ""; // digitalSignature, nonRepudiation
    strcpy(szBuf, szKeyUsage);
    nLen = strlen(szBuf);
    iRV = X509_REQ_add1_attr_by_txt(pX509Req, "keyUsage", V_ASN1_UTF8STRING, szBuf, nLen);
    
    char szExKeyUsage[] = ""; // serverAuth, clientAuth
    strcpy(szBuf, szExKeyUsage);
    nLen = strlen(szBuf);
    iRV = X509_REQ_add1_attr_by_txt(pX509Req, "extendedKeyUsage", V_ASN1_UTF8STRING, szBuf, nLen);
    
//    // 添加扩展项
//    STACK_OF(X509_EXTENSION) *pX509Ext = NULL;
//    iRV = X509_REQ_add_extensions(pX509Req, pX509Ext);
    
    STACK_OF(X509_EXTENSION) *pX509Ext = sk_X509_EXTENSION_new_null();
    
//    X509_EXTENSION *pX509EXT = NULL;
//    const char *name = "basicConstraints";
//    const char *value = "";
//    pX509EXT = X509V3_EXT_conf(NULL, NULL, name, value);
//    // 生成扩展对象
//    sk_X509_EXTENSION_push(pX509Ext, pX509EXT);
    
    // 加入扩展项目
    X509_REQ_add_extensions(pX509Req, pX509Ext);
    
    // 用主体结构私钥对上面的req进行签名
    // 签名方式为哈希（非MD5）
    // 摘要
    // EVP_MD 结构用来存放摘要算法信息以及各种计算函数。
    /*
     struct evp_md_st
     {
     int type;  //摘要类型，一般是摘要算法 NID
     int pkey_type;  //公钥类型，一般是签名算法 NID
     int md_size;  //摘要值大小，为字节数
     unsigned long flags;  //用于设置标记
     // 摘要算法初始化函数
     int (*init) (EVP_MD_CTX *ctx);
     // 多次摘要函数
     int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
     // 摘要完结函数
     int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
     // 摘要上下文结构复制函数
     int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
     // 清除摘要上下文函数
     int (*cleanup) (EVP_MD_CTX *ctx);
     int block_size;
     int ctx_size;               // how big does the ctx->md_data need to be
     // control function
     int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
     };
     */
    
    md = EVP_sm3();
//    md = EVP_sha1();
    int id = EVP_MD_type(md);
    int id2 = EVP_MD_pkey_type(md);
    int id3 = EVP_MD_size(md);
    printf("摘要算法 NID: %d, 签名算法 NID: %d, 长度: %d\n\n", id, id2, id3);
    
    ////    OpenSSL_add_all_algorithms();
    //    OpenSSL_add_all_digests();
    ////    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    //
    //    int n = 1204;
    //    const EVP_MD *md2 = NULL;
    //    md2 = EVP_get_digestbynid(n);
    //
    //    if(md2 != NULL)
    //    {
    //        int id3 = EVP_MD_type(md2);
    //        int id4 = EVP_MD_pkey_type(md2);
    //        printf("摘要算法 NID: %d, 签名算法 NID: %d\n\n", id3, id4);
    //    }
    //    else
    //    {
    //        printf("NULL!\n");
    //        printf("\n");
    //    }
    
    // 计算消息摘要: mdout为结果，nModLen为结果的长度 (摘要不可逆推原文)
    iRV = X509_REQ_digest(pX509Req, md, mdout, &nModLen);
    printf("nModLen: %d\n", nModLen);
    printf("mdout: ");
    for (int i=0; i<nModLen; i++) {
        printf("%02x", mdout[i]);
    }
    printf("\n\n");
    
    // 用私钥对摘要签名
    iRV = X509_REQ_sign(pX509Req, pEVPKey, md);
    if(!iRV)
    {
        printf("sign err!\n\n");
        X509_REQ_free(pX509Req);
        return -1;
    }
    
    // 写入文件PEM格式
    //     pBIO = BIO_new_file("certreq.txt", "w");
    //     PEM_write_bio_X509_REQ(pBIO, pX509Req, NULL, NULL);
    //     BIO_free(pBIO);
    
    // 2.1  返回PEM字符  PKCS10证书请求
    pPemBIO = BIO_new(BIO_s_mem());
    //    PEM_write_bio_X509_REQ(pPemBIO, pX509Req, NULL, NULL);
    PEM_write_bio_X509_REQ(pPemBIO, pX509Req);
    BIO_get_mem_ptr(pPemBIO,&pBMem);
    if(pBMem->length <= nCSRSize)
    {
        memcpy(pCSR, pBMem->data, pBMem->length);
    }
    BIO_free(pPemBIO);
    
    // 2.2 获取公钥 PEM_read_bio_PUBKEY   PEM_read_bio_RSA_PUBKEY PEM_write_bio_RSAPublicKey
    char publicKey[2048] = {0};
    pPemBIO = BIO_new(BIO_s_mem());
    //    if (PEM_write_bio_PUBKEY(pPemBIO,pEVPKey)!=1){
    //       printf("pulic key error\n");
    //    }
    if (PEM_write_bio_RSA_PUBKEY(pPemBIO,pRSA)!=1){
        printf("pulic key error\n");
    }
    //    if (PEM_write_bio_RSAPublicKey(pPemBIO,pRSA)!=1){
    //        printf("pulic key error\n");
    //    }
    
    // 公钥转换输出
    BIO_get_mem_ptr(pPemBIO,&pBMem);
    if(pBMem->length <= nCSRSize)
    {
        memcpy(publicKey, pBMem->data, pBMem->length);
    }
    BIO_free(pPemBIO);
    printf("公钥：\n%s\n",publicKey);
    
    
    
    // 2.3 获取私钥
    char priKey[2048] = {0};
    char passwd[] = "123";  // 对私钥进行加密的密码
    pPemBIO = BIO_new(BIO_s_mem());
    //    if (PEM_write_bio_RSAPrivateKey(pPemBIO, pRSA, EVP_des_ede3(), (unsigned char *)passwd, 4, NULL, NULL)!=1) {
    //        printf("private key error\n");
    //    }
    if (PEM_write_bio_RSAPrivateKey(pPemBIO, pRSA,NULL, NULL, 0, NULL, NULL)!=1) {
        printf("private key error\n");
    }
    
    // 私钥转换输出
    BIO_get_mem_ptr(pPemBIO,&pBMem);
    if(pBMem->length <= nCSRSize)
    {
        memcpy(privateKey, pBMem->data, pBMem->length);
    }
    
    BIO_free(pPemBIO);
    printf("私钥：\n%s\n",privateKey);
    
    /* DER编码 */
    //nLen = i2d_X509_REQ(pX509Req, NULL);
    //pDer = (unsigned char *)malloc(nLen);
    //p = pDer;
    //nLen = i2d_X509_REQ(pX509Req, &p);
    //free(pDer);
    
    // 验证CSR
    OpenSSL_add_all_algorithms();
    // 对签名进行验证，并传入公钥
    iRV = X509_REQ_verify(pX509Req, pEVPKey);
    if(iRV<0)
    {
        printf("verify err.\n");
    }
    
    X509_REQ_free(pX509Req);
    
    //     输出pkcs10CSR证书请求
    //    printf("CSR:\n%s", pCSR);
    
    return nCSRSize;
}


int main()
{
    /* 生成pkcs10 证书请求  格式：/CN=参数1/O=参数2/OU=参数3……
     * 例如："/CN=www.cicc.com/O=cicc.com/OU=IT/ST=Beijing City/L=beijing/C=CN/emailAddress=934800996@qq.com"
     * CN: 通用名称，域名  Common Name
     * O:  组织          Organization
     * OU: 部门          Organizational Unit
     * ST:  省份          State
     * L:  城市          Locality
     * C:  国家          Country
     */
    
    char chDN[255] = "/CN=KGWRoot/O=CDRMLAB/C=CN";
    char chCSR[2048] = {0};
    char privateKey[2048] = {0};
    long int rv = GenCSR(chDN, strlen(chDN), chCSR, sizeof(chCSR),privateKey);
    
    printf("PKCS10（CSR）:\n%s", chCSR);
    //    printf("privateKey:\n%s", privateKey);
    
    return 0;
}
