#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define KEY_SIZE 32
#define IV_SIZE 16
#define SALT_SIZE 8
#define __PRINT_DEBUG__
//#undef __PRINT_DEBUG__

int decrypt_def_openssl_encoded_content(const unsigned char* encrypted, int len, const char* szPassword )
{
    FILE *wfp = fopen("output.dec","wb");
    unsigned int srcRemain;
    unsigned int outLen;
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char* pEnc;
    unsigned char* decBuf = malloc(len);
    int ret = -1;

    EVP_CIPHER_CTX *ctx = NULL;

    if (wfp == NULL) {
        fprintf(stderr,"[ERROR] %d can not fopen('%s')\n", __LINE__, "output.dec");
        return -1;

    }

    // 암호화된 파일은 salt가 적용되어 있기 때문에 16byte 보다는 큼.
    // ==> Salt signature(8byte) + Salt data(8byte) = 총 16byte
    if (len < (SALT_SIZE * 2)) {
        fprintf( stderr, "file is too short < 16 bytes\n" );
        return -1;
    }

    // Salt 값을 추출, Salt signature(8byte)는 건너띄고 Salt data(8byte) 만큼만 추출.
    memcpy(salt, encrypted + SALT_SIZE, SALT_SIZE);

#ifdef __PRINT_DEBUG__
    printf("salt : ");
    for (int i = 0; i < SALT_SIZE; i++) {
        printf("%02X ", salt[i]);
    }
    printf("\n");
#endif

    // 1. Salt 데이터와 비밀번호를 기반으로 key와 iv를 추출
    // 2. EVP_BytesToKey 함수의 6번재 인수인 count에 1을 전달, 이는 암호화시에 사용하는 openssl 커맨드에서 해당 값을 디폴트 1로 사용하기 때문.
    if (0 == EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (unsigned char*)szPassword, strlen(szPassword), 1, key, iv)) {
        fprintf(stderr, "key iv deriving failure\n");
        goto last;
    }

#ifdef __PRINT_DEBUG__
    printf("key : ");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02X", key[i]);
    }
    printf("\niv : ");
    for (int i = 0; i < IV_SIZE; i++) {
        printf("%02X", iv[i]);
    }
    printf("\n");
#endif

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "create context failure");
        goto last;
    }

    if (!EVP_DecryptInit_ex( ctx, EVP_aes_256_cbc(), NULL, key, iv )) {
        fprintf(stderr, "EVP_DecryptInit_ex error\n");
        goto last;
    }

    // 암호화된 데이터를 전달하여, 복호화된 데이터를 생성한다.
    // 복호화시에 Salt signature(8byte) + Salt data(8byte)는 포함하지 않는다.
    srcRemain = len - (SALT_SIZE * 2);
    pEnc = (unsigned char*)encrypted + (SALT_SIZE * 2);
    memset(decBuf, 0x0, sizeof(decBuf));
    if (1 != EVP_DecryptUpdate(ctx, decBuf, &outLen, pEnc, srcRemain)) {
        fprintf(stderr, "error while decrypting\n");
        goto last;
    }

    fwrite(decBuf ,1 ,outLen + 8 ,wfp);
    if (1 != EVP_DecryptFinal_ex(ctx, decBuf, &outLen)) {
        fprintf(stderr, "error while final can be invalid password, or corrupted\n");
        goto last;
    }

    ret = 0;

    last:

    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    if (wfp) {
        fclose(wfp);
        wfp = NULL;
    }

    return ret;
}

int decrypt_def_openssl_encoded_file(const char* szEncFileName, const char* szPassword) {
    FILE* fp = fopen(szEncFileName, "rb");
    unsigned char* encContent = NULL;
    unsigned int fileSize;
    int ret = -1;

    if (!fp) {
        fprintf(stderr, "can't open file %s", szEncFileName);
        goto last;
    }

    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);

    encContent = (unsigned char*)malloc(fileSize);

    fseek(fp, 0, SEEK_SET);
    fread(encContent, 1, fileSize, fp);

    ret = decrypt_def_openssl_encoded_content(encContent, fileSize, szPassword);

    last:

    if (encContent) {
        free(encContent);
    }

    if (fp) {
        fclose(fp);
        fp = NULL;
    }

    return ret;
}

int main(int argc, char *args[])
{
    if (argc != 3) {
        printf("[Usage] %s test.txt password\n",args[0]);
        return -1;
    }

    decrypt_def_openssl_encoded_file(args[1], args[2]);

    return 0;
}
