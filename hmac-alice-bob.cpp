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

    // rewind함수는 매개변수로 들어온 스트림을 초기화하는데 사용
    rewind(stdin);

    strncpy(bob_mac, MakeBobMAC(), 128);


    if (VerifyMAC(alice_mac, bob_mac) == true)
        printf("\nAlice와 BoB의 MAC은 같습니다.\n");
    else
        printf("\nAlice와 BoB의 MAC은 다릅니다.\n");

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
    scanf("%[^\n]", &input1); //%[^  ]는 [] 안에 들어간 요소를 만나면 받는걸 멈춤
    unsigned char* message=(unsigned char* )input1;
    
    fflush(stdin);

    printf("Input Alice Key: ");
    scanf("%*s", &input2); //// \n 읽어서 버림
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
    if (strcmp(alice_mac, bob_mac) == 0) return true; // 같다
    else return false;
}