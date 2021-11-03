#include<Windows.h>
#include<stdio.h>
#include<time.h>

#pragma comment(lib,"crypt32.lib")

#define SAFE_FREE_BLOB(x) {\
    if(x.cbData && x.pbData)\
    {\
        LocalFree(x.pbData);\
        x.pbData = 0;\
        x.cbData =0;\
    }}


const char Versions[3][8] = {
    "2015",
    "2017",
    "2019"
};

const char Path[3][64] = {
"Licenses\\4D8CFBCB-2F6A-4AD2-BABF-10E28F6F2C8F\\07078",        //2015
"Licenses\\5C505A59-E312-4B89-9508-E162F8150517\\08878" ,       //2017
"Licenses\\41717607-F34E-432C-A138-A3CFD7E25CDA\\09278"         //2019
};


typedef struct _DateStrt
{
    short int Year;
    short int Mon;
    short int Day;
    unsigned char another[6];
}DateStrt;


void ResetData(BYTE* Data,DWORD DataSize)
{
    if (DataSize < 16)
    {
        return;
    }

    DateStrt* pDate = (Data + DataSize - 16);
    
    time_t t;
    struct tm* p;
    time(&t);
    t += 30 * 24 * 60 * 60;     //next mon
    p = localtime(&t);
    pDate->Year = 1900 + p->tm_year;
    pDate->Mon = 1 + p->tm_mon;
    pDate->Day = p->tm_mday;
    
}


void ReadReg()
{
    HKEY hKey;
    DWORD KeyType = REG_BINARY;
    DWORD DataSize;
    BYTE Binary[2048] = { 0 };

    DataSize = sizeof(Binary);

    DATA_BLOB DataIn = { 0 }, DataOut = { 0 }, DataEnc = { 0 };

    for (int i = 0; i < sizeof(Path) / sizeof(Path[0]); i++)
    {
        SAFE_FREE_BLOB(DataOut);
        SAFE_FREE_BLOB(DataEnc);
        long ret = (RegOpenKeyExA(HKEY_CLASSES_ROOT, Path[i], 0, KEY_READ|KEY_WRITE|KEY_WOW64_64KEY, &hKey));

        if (ret == ERROR_SUCCESS)
        {
            do {

                ret = RegQueryValueExA(hKey, NULL, 0, &KeyType, (LPBYTE)Binary, &DataSize);
                if (ret == ERROR_SUCCESS)
                {
                    DataIn.pbData = Binary;
                    DataIn.cbData = DataSize;
                    DataOut.pbData = 0;
                    DataOut.cbData = 0;

                    if (!CryptUnprotectData(&DataIn, 0, 0, 0, 0, 0, &DataOut))
                    {
                        continue;
                    }

                    if (DataOut.cbData == 0 || DataOut.pbData == 0)
                    {
                        continue;
                    }

                    ResetData(DataOut.pbData, DataOut.cbData);

                    DataEnc.cbData = 0;
                    DataEnc.pbData = 0;

                    if (!CryptProtectData(&DataOut, 0, 0, 0, 0, 0, &DataEnc))
                    {
                        continue;
                    }

                    if (DataEnc.cbData == 0 || DataEnc.pbData == 0)
                    {
                        continue;
                    }

                    if (RegSetKeyValueA(hKey, NULL, 0, KeyType, DataEnc.pbData, DataEnc.cbData) == ERROR_SUCCESS)
                    {
                        printf("%s Reset Successed\n", Versions[i]);
                    }
                    else
                    {
                        printf("%s Reset error with %d\n", Versions[i], GetLastError());
                    }

                }
            } while (0);
            RegCloseKey(hKey);
        }

    }


    SAFE_FREE_BLOB(DataOut);
    SAFE_FREE_BLOB(DataEnc);

}


int main(int argc, char* argv[])
{
    ReadReg();

    return 0;
}