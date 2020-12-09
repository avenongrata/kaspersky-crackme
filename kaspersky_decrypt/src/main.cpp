#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

const int globalFileLen = 0x1048;
char globalConstData[globalFileLen];

int globalEncFileLen;
char *globalEncryptedData;

typedef struct {
    unsigned char b0;
    unsigned char b1;
    unsigned char b2;
    unsigned char b3;
    unsigned char b4;
    unsigned char b5;
    unsigned char b6;
    unsigned char b7;
} _KEY_PART;

void getConstData(void);
void decrypt(_KEY_PART);
void decryptStage2(int, int *, int);
void showRegister(int, int, int, int, int);
void getEncryptedData();
int getFromConstData(int);


int main()
{
    getConstData();
    getEncryptedData();
    _KEY_PART key;

    for (int i = 0; i < globalEncFileLen; i += 8){
        key.b0 = globalEncryptedData[i];
        key.b1 = globalEncryptedData[i+1];
        key.b2 = globalEncryptedData[i+2];
        key.b3 = globalEncryptedData[i+3];
        key.b4 = globalEncryptedData[i+4];
        key.b5 = globalEncryptedData[i+5];
        key.b6 = globalEncryptedData[i+6];
        key.b7 = globalEncryptedData[i+7];
        decrypt(key);
    }

    delete [] globalEncryptedData;

    return 0;
}

void getEncryptedData()
{
    std::streampos size;
    std::string path = "protected_key.dat";

    // fill array with const data
    std::ifstream file (path, std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        size = file.tellg();
        file.seekg(0, std::ios::beg);
        globalEncryptedData = new char [size];
        globalEncFileLen = (int)size;
        file.read(globalEncryptedData, size);
        file.close();
    } else {
        std::cout << "Can't open file with data\n";
        exit (0);
    }
}

void showRegister(int eax, int ebx, int edx, int esi, int edi)
{
    std::cout << "EAX:  " << std::hex << eax << std::endl;
    std::cout << "EBX:  " << std::hex << ebx << std::endl;
    std::cout << "EDX:  " << std::hex << edx << std::endl;
    std::cout << "ESI:  " << std::hex << esi << std::endl;
    std::cout << "EDI:  " << std::hex << edi << std::endl << std::endl;
}

int getFromConstData(int offset)
{
    /*
     * This function allow to get dword from const data
     */

    struct {
        unsigned char b0;
        unsigned char b1;
        unsigned char b2;
        unsigned char b3;
    } _INT;

    int _dword = 0;

    _INT.b0 = globalConstData[offset+3];
    _INT.b1 = globalConstData[offset+2];
    _INT.b2 = globalConstData[offset+1];
    _INT.b3 = globalConstData[offset];

    _dword = _dword | _INT.b0;
    _dword = _dword << 8;
    _dword = _dword | _INT.b1;
    _dword = _dword << 8;
    _dword = _dword | _INT.b2;
    _dword = _dword << 8;
    _dword = _dword | _INT.b3;

    return _dword;
}

void getConstData()
{
    std::streampos size;
    std::string path = "const_data_1048_byte.dat";

    // fill array with const data
    std::ifstream file (path, std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        size = file.tellg();
        file.seekg(0, std::ios::beg);
        file.read(globalConstData, size);
        file.close();
    } else {
        std::cout << "Can't open file with data\n";
        exit (0);
    }
}

void decryptStage2(int _register, int *_esi, int _edi)
{
    int t_esi = *_esi;
    int t_edi = _edi;
    int t_register = _register;
    int t_dword;

    t_esi = t_register;
    t_edi = t_register;

    __asm {
        mov esi, t_esi          ;
        mov edi, t_edi          ;
        shr esi, 0x10           ;
        shr edi, 0x18           ;
        mov edx, esi            ;
        movzx esi, dl           ;

        mov t_edi, edi          ;
        mov t_esi, esi          ;
    }

    //################# second half #################

    t_esi = getFromConstData(t_esi*4+0x448);
    t_dword = getFromConstData(t_edi*4+0x48);

    __asm {
        mov esi, t_esi          ;
        add esi, t_dword        ;

        push eax                ;
        mov eax, t_register     ;
        movzx edi, ah           ;

        pop eax                 ;
        mov t_edi, edi          ;
        mov t_esi, esi          ;
    }

    t_esi ^= getFromConstData(t_edi*4+0x848);

    __asm {
        push eax                ;
        mov eax, t_register     ;
        movzx edi, al           ;

        pop eax                 ;
        mov t_edi, edi          ;
    }

    t_dword = getFromConstData(t_edi*4+0xc48);

    __asm {
        mov esi, t_esi;
        add esi, t_dword;

        mov t_esi, esi;
    }

    *_esi = t_esi;
}

void decrypt(_KEY_PART key)
{

    int _eax, _ebx, _edx, _esi, _edi;
    int dwordFromConstData = 0;

    _eax = 0;
    _eax |= key.b0;
    _eax <<= 8;
    _eax |= key.b1;
    _eax <<= 8;
    _eax |= key.b2;
    _eax <<= 8;
    _eax |= key.b3;

    _ebx = 0;
    _ebx |= key.b4;
    _ebx <<= 8;
    _ebx |= key.b5;
    _ebx <<= 8;
    _ebx |= key.b6;
    _ebx <<= 8;
    _ebx |= key.b7;

    _eax ^= getFromConstData(0x44);

    _esi = _eax;
    _edi = _eax;

    __asm {
        mov esi, _esi           ;
        mov edi, _edi           ;

        shr esi, 0x10           ;
        shr edi, 0x18           ;

        mov edx, esi            ;
        movzx esi, dl           ;

        mov _edx, edx           ;
        mov _edi, edi           ;
        mov _esi, esi           ;
    }

    _esi = getFromConstData(_esi*4+0x448);
    dwordFromConstData = getFromConstData(_edi*4+0x48);

    __asm {
        mov esi, _esi                       ;
        add esi, dwordFromConstData         ;

        mov eax, _eax                       ;
        movzx edi, ah                       ;

        mov _edi, edi                       ;
        mov _esi, esi                       ;
    }

    __asm {
        mov eax, _eax           ;
        movzx edi, ah           ;

        mov _edi, edi           ;
    }

    _esi ^= getFromConstData(_edi*4+0x848);

    __asm {
        mov eax, _eax           ;
        movzx edi, al           ;

        mov _edi, edi           ;
    }

    dwordFromConstData = getFromConstData(_edi*4+0xC48);

    __asm {
        mov esi, _esi                       ;
        add esi, dwordFromConstData         ;

        mov _esi, esi                       ;
    }

    _ebx ^= _esi;       // now i know EAX and EBX

    // ################# stage 2 #################

    _ebx ^= getFromConstData(0x40);
    decryptStage2(_ebx, &_esi, _edi);
    _eax ^= _esi;

    _eax ^= getFromConstData(0x3c);
    decryptStage2(_eax, &_esi, _edi);
    _ebx ^= _esi;
    _ebx ^= getFromConstData(0x38);

    decryptStage2(_ebx, &_esi, _edi);
    _eax ^= _esi;
    _eax ^= getFromConstData(0x34);
    decryptStage2(_eax, &_esi, _edi);
    _ebx ^= _esi;
    _ebx ^= getFromConstData(0x30);
    decryptStage2(_ebx, &_esi, _edi);
    _eax ^= _esi;
    _eax ^= getFromConstData(0x2c);


    // ################# different behavior START  #################

    _edi = _eax;
    _esi = _eax;

    __asm {
        mov esi, _esi           ;
        mov edi, _edi           ;

        shr edi, 0x18           ;
        shr esi, 0x10           ;

        mov _esi, esi           ;
        mov _edi, edi           ;
    }

    _ebx ^= getFromConstData(0x28);
    _edx = _esi;

    __asm {
        mov esi, _esi;
        mov edx, _edx;

        movzx esi, dl;

        mov _esi, esi;
    }

    _esi = getFromConstData(_esi*4+0x448);
    dwordFromConstData = getFromConstData(_edi*4+0x48);

    __asm {
        mov esi, _esi                       ;
        add esi, dwordFromConstData         ;

        mov eax, _eax                       ;
        movzx edi, ah                       ;

        mov _edi, edi                       ;
        mov _esi, esi                       ;
    }

    _esi ^= getFromConstData(_edi*4+0x848);

    __asm {
        mov eax, _eax           ;
        movzx edi, al           ;

        mov _edi, edi           ;
    }

    dwordFromConstData = getFromConstData(_edi*4+0xc48);

    __asm {
        mov esi, _esi;
        add esi, dwordFromConstData;

        mov _esi, esi;
    }

    // ################# different behavior STOP  #################

    _ebx ^= _esi;
    decryptStage2(_ebx, &_esi, _edi);
    _eax ^= _esi;
    _eax ^= getFromConstData(0x24);
    decryptStage2(_eax, &_esi, _edi);
    _ebx ^= _esi;
    _ebx ^= getFromConstData(0x20);
    decryptStage2(_ebx, &_esi, _edi);
    _eax ^= _esi;
    _eax ^= getFromConstData(0x1c);
    decryptStage2(_eax, &_esi, _edi);
    _ebx ^= _esi;
    _ebx ^= getFromConstData(0x18);
    decryptStage2(_ebx, &_esi, _edi);
    _eax ^= _esi;
    _eax ^= getFromConstData(0x14);
    decryptStage2(_eax, &_esi, _edi);
    _ebx ^= _esi;
    _ebx ^= getFromConstData(0x10);
    decryptStage2(_ebx, &_esi, _edi);
    _eax ^= _esi;
    _eax ^= getFromConstData(0xc);
    decryptStage2(_eax, &_esi, _edi);
    _ebx ^= _esi;

    // ################# stage 3 #################

    int t_register_eax;

    _ebx ^= getFromConstData(0x8);
    _esi = _ebx;
    t_register_eax = _ebx;

    __asm {
        mov esi, _esi               ;
        shr esi, 0x10               ;

        push eax;
        mov eax, t_register_eax     ;
        shr eax, 0x18               ;

        mov edx, esi                ;
        movzx esi, dl               ;

        mov _edi, edi               ;
        mov _esi, esi               ;
        mov _edx, edx               ;
        mov t_register_eax, eax     ;
    }

    _esi = getFromConstData(_esi*4+0x448);
    dwordFromConstData = getFromConstData(t_register_eax*4+0x48);

    __asm {
        mov esi, _esi                       ;
        add esi, dwordFromConstData         ;

        push edx                            ;
        mov ebx, _ebx                       ;
        movzx edx, bh                       ;
        mov t_register_eax, edx             ;
        pop edx                             ;

        mov _esi, esi                       ;
    }

    _esi ^= getFromConstData(t_register_eax*4+0x848);

    __asm {
        mov ebx, _ebx                       ;

        push edx                            ;
        movzx edx, bl                       ;
        mov t_register_eax, edx             ;
        pop edx;
    }

    dwordFromConstData = getFromConstData(t_register_eax*4+0xC48);

    __asm {
        mov esi, _esi;
        add esi, dwordFromConstData;

        mov _esi, esi;
    }

    _eax ^= _esi;
    _edi = getFromConstData(0x4);
    _edi ^= _eax;

    __asm {
        mov edi, _edi           ;
        bswap edi               ;
        mov _edi, edi           ;
    }

    _ebx ^= getFromConstData(0x0);

    __asm {
        mov ebx, _ebx           ;
        bswap ebx               ;
        mov _ebx, ebx           ;
    }

    // ################# FINAL #################

    // It works only when I open file current here. Wtf? optimization is in trash
    std::string path = "decrypted_text.dat";
    std::fstream dec_file;
    dec_file.open (path, std::ios::binary | std::ios::app);
    unsigned char byte;

    for (int i = 0; i < 8; i++) {
        if (i > 3) {
            byte = (_edi >> (8*i)) & 0xff;
            dec_file << byte;
            continue;
        }
        byte = (_ebx >> (8*i)) & 0xff;
        dec_file << byte;
    }
    dec_file.close();
}
