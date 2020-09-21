#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/hmac.h>

char* MakeAliceMAC();
char* MakeBobMAC();
bool VerifyMAC(char* alice_mac, char* bob_mac);

int main()
{
    char alice_mac[128];
    char bob_mac[128];

    strncpy(alice_mac, MakeAliceMAC(), 128);

    // rewind�Լ��� �Ű������� ���� ��Ʈ���� �ʱ�ȭ�ϴµ� ���
    rewind(stdin);

    strncpy(bob_mac, MakeBobMAC(), 128);


    if (VerifyMAC(alice_mac, bob_mac) == true)
        printf("\nAlice�� BoB�� MAC�� �����ϴ�.\n");
    else
        printf("\nAlice�� BoB�� MAC�� �ٸ��ϴ�.\n");

    return 0;
}


char* MakeAliceMAC()
{
    char input1[20];
    char input2[20];
    unsigned char* result;
    unsigned int result_len = 32;
    static char res_hexstring[64];

    printf("\nInput Alice Message: ");
    scanf("%[^\n]", &input1); //%[^  ]�� [] �ȿ� �� ��Ҹ� ������ �޴°� ����
    unsigned char* message=(unsigned char* )input1;
    
    fflush(stdin);

    printf("Input Alice Key: ");
    scanf("%*s", &input2); //// \n �о ����
    unsigned char* key= (unsigned char*)input2;

    result = HMAC(EVP_sha256(), key, strlen((char*)key), message, strlen((char*)message), NULL, NULL);

    for (int i = 0; i < result_len; i++) {
        sprintf(&(res_hexstring[i * 2]), "%02x", result[i]);
    }

    printf("Alice MAC = %s\n", res_hexstring);

    return res_hexstring;
}


char* MakeBobMAC()
{
    char input1[20];
    char input2[20];

    unsigned char* result;
    unsigned int result_len = 32;
    static char res_hexstring[64];

    printf("\nInput Bob Message: ");
    scanf("%[^\n]", &input1);
    unsigned char* message = (unsigned char*)input1;
    
    fflush(stdin);
    
    printf("Input Bob Key: ");
    scanf("%*s", &input2);
    unsigned char* key = (unsigned char*)input2;

    result = HMAC(EVP_sha256(), key, strlen((char*)key), message, strlen((char*)message), NULL, NULL);

    for (int i = 0; i < result_len; i++) {
        sprintf(&(res_hexstring[i * 2]), "%02x", result[i]);
    }

    printf("Bob MAC = %s\n", res_hexstring);

    return res_hexstring;
}


bool VerifyMAC(char* alice_mac, char* bob_mac)
{
    if (strcmp(alice_mac, bob_mac) == 0) return true; // ����
    else return false;
}