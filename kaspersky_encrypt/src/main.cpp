#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

//------------------------------------------------------------------------------

const int globalFileLen = 0x1048;
char globalConstData[globalFileLen];

//------------------------------------------------------------------------------

void genKey(int, int);
void genKeyStage2(int *, int *, int *, int *);
void genKeyStage3(int *, int);
void getConstData(void);
int getFromConstData(int);

//------------------------------------------------------------------------------

int main()
{
    int dword_1, dword_2;
    dword_1 = 0x19f37f07;       // test
    dword_2 = 0xe03b57e7;       // test

    getConstData();
    genKey(dword_1, dword_2);

    return 0;
}

//------------------------------------------------------------------------------

void genKeyStage3(int * _esi, int _edi)
{
    /*
     * add esi,dword ptr ds:[ecx+edi*4+C48]
     */

    int t_esi = *_esi;
    int t_dword = getFromConstData(_edi*4+0xc48);

    __asm
    {
        mov esi, t_esi;
        add esi, t_dword;

        mov t_esi, esi;
    }

    *_esi = t_esi;
}

//------------------------------------------------------------------------------

void genKeyStage2(int * _register, int * _esi, int * _edi, int * _edx)
{
    /*
     *
     * xor eax,esi
     * mov esi,eax
     * mov edi,eax
     * shr esi,10
     * shr edi,18
     * mov edx,esi
     * movzx esi,dl
     *
     * mov esi,dword ptr ds:[ecx+esi*4+448]
     * add esi,dword ptr ds:[ecx+edi*4+48]
     * movzx edi,ah
     * xor esi,dword ptr ds:[ecx+edi*4+848]
     * movzx edi,al
     *
     * =========================================================================
     *
     * xor ebx,esi
     * mov esi,ebx
     * mov edi,ebx
     * shr esi,10
     * shr edi,18
     * mov edx,esi
     * movzx esi,dl
     *
     * mov esi,dword ptr ds:[ecx+esi*4+448]
     * add esi,dword ptr ds:[ecx+edi*4+48]
     * movzx edi,bh
     * xor esi,dword ptr ds:[ecx+edi*4+848]
     * movzx edi,bl
     *
     */

    int t_esi = *_esi;
    int t_edi = *_edi;
    int t_edx = *_edx;
    int t_register = *_register;
    int t_dword;

    // ======================== first half ========================

    t_register ^= t_esi;
    t_esi = t_register;
    t_edi = t_register;

    __asm
    {
        mov esi, t_esi          ;
        mov edi, t_edi          ;
        shr esi, 0x10           ;
        shr edi, 0x18           ;
        mov edx, esi            ;
        movzx esi, dl           ;

        mov t_edx, edx          ;
        mov t_edi, edi          ;
        mov t_esi, esi          ;
    }

    // ======================== second half ========================

    t_esi = getFromConstData(t_esi*4+0x448);
    t_dword = getFromConstData(t_edi*4+0x48);

    __asm
    {
        mov esi, t_esi          ;
        add esi, t_dword        ;

        push eax                ;
        mov eax, t_register     ;
        movzx edi, ah           ;

        pop eax                 ;
        mov t_edi, edi          ;
        mov t_esi, esi          ;
    }

    //--------------------------------------------------------------------------

    t_dword = getFromConstData(t_edi*4+0x848);
    t_esi = t_esi ^ t_dword;

    __asm
    {
        push eax                ;
        mov eax, t_register     ;
        movzx edi, al           ;

        pop eax                 ;
        mov t_edi, edi          ;
    }

    //--------------------------------------------------------------------------

    *_esi = t_esi;
    *_edi = t_edi;
    *_edx = t_edx;
    *_register = t_register;
}

//------------------------------------------------------------------------------

void getConstData()
{
    std::streampos size;
    std::string path = "const_data_1048_byte.dat";

    // fill array with const data
    std::ifstream file (path, std::ios::binary | std::ios::ate);
    if (file.is_open())
    {
        size = file.tellg();
        file.seekg(0, std::ios::beg);
        file.read(globalConstData, size);
        file.close();
    }
    else
    {
        std::cout << "Can't open file with data\n";
        exit (0);
    }
}

//------------------------------------------------------------------------------

int getFromConstData(int offset)
{
    /*
     * This function allow to get dword from const data
     */

    struct
    {
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

//------------------------------------------------------------------------------

void genKey(int dataDword1, int dataDword2)
{
    struct
    {
        unsigned char b0;
        unsigned char b1;
        unsigned char b2;
        unsigned char b3;
        unsigned char b4;
        unsigned char b5;
        unsigned char b6;
        unsigned char b7;
    } _KEY_PART;

    int _eax, _ebx, _ecx, _edx, _esi, _edi;
    int dwordFromConstData = 0;

    // ======================== stage 1 ========================

    _ebx = dataDword1;
    _edi = dataDword2;

    __asm
    {
        mov ebx, _ebx       ;
        bswap ebx           ;
        mov _ebx, ebx       ;
    }

    //--------------------------------------------------------------------------

    dwordFromConstData = getFromConstData(0);
    _ebx ^= dwordFromConstData;

    //--------------------------------------------------------------------------

    __asm
    {
        mov edi, _edi       ;
        bswap edi           ;
        mov _edi, edi       ;
    }

    //--------------------------------------------------------------------------

    _esi = _ebx;
    _eax = _ebx;

    __asm
    {
        mov esi, _esi       ;
        mov eax, _eax       ;
        shr esi, 0x10       ;
        shr eax, 0x18       ;
        mov _esi, esi       ;
        mov _eax, eax       ;
    }

    //--------------------------------------------------------------------------

    _edx = _esi;

    __asm
    {
        mov esi, _esi       ;
        mov edx, _edx       ;
        movzx esi, dl       ;
        mov _esi, esi       ;
    }

    //--------------------------------------------------------------------------

    _esi = getFromConstData(_esi*4+0x448);
    dwordFromConstData = getFromConstData(_eax*4+0x48);

    __asm
    {
        mov esi, _esi               ;
        add esi, dwordFromConstData ;
        mov _esi, esi               ;

        mov eax, _eax               ;
        mov ebx, _ebx               ;
        movzx eax, bh               ;
        mov _eax, eax               ;
    }

    //--------------------------------------------------------------------------

    _esi = _esi ^ (getFromConstData(_eax*4+0x848));

    //--------------------------------------------------------------------------

    __asm
    {
        mov eax, _eax       ;
        mov ebx, _ebx       ;
        movzx eax, bl       ;
        mov _eax, eax       ;
    }

    //--------------------------------------------------------------------------

    _ebx = _ebx ^ (getFromConstData(0x8));
    dwordFromConstData = getFromConstData(_eax*4+0xc48);

    __asm
    {
        mov esi, _esi               ;
        add esi, dwordFromConstData ;

        mov _esi, esi               ;
    }

    //--------------------------------------------------------------------------

    _eax = getFromConstData(4);
    _eax ^= _edi;

    // ======================== stage 2 ========================

    genKeyStage2(&_eax, &_esi, &_edi, &_edx);
    _eax ^= getFromConstData(0xc);
    genKeyStage3(&_esi, _edi);

    //--------------------------------------------------------------------------

    genKeyStage2(&_ebx, &_esi, &_edi, &_edx);
    _ebx ^= getFromConstData(0x10);
    genKeyStage3(&_esi, _edi);

    //--------------------------------------------------------------------------

    genKeyStage2(&_eax, &_esi, &_edi, &_edx);
    genKeyStage3(&_esi, _edi);

    //--------------------------------------------------------------------------

    genKeyStage2(&_ebx, &_esi, &_edi, &_edx);
    _eax ^= getFromConstData(0x14);
    genKeyStage3(&_esi, _edi);
    _ebx ^= getFromConstData(0x18);

    //--------------------------------------------------------------------------

    genKeyStage2(&_eax, &_esi, &_edi, &_edx);
    _eax ^= getFromConstData(0x1c);
    genKeyStage3(&_esi, _edi);

    //--------------------------------------------------------------------------

    genKeyStage2(&_ebx, &_esi, &_edi, &_edx);
    _ebx ^= getFromConstData(0x20);
    genKeyStage3(&_esi, _edi);

    //--------------------------------------------------------------------------

    genKeyStage2(&_eax, &_esi, &_edi, &_edx);
    _eax ^= getFromConstData(0x24);
    genKeyStage3(&_esi, _edi);

    //--------------------------------------------------------------------------

    genKeyStage2(&_ebx, &_esi, &_edi, &_edx);
    genKeyStage3(&_esi, _edi);

    // ====================== different behavior START  ======================

    _eax ^= _esi;
    _edi = _eax;
    _esi = _eax;

    __asm
    {
        mov esi, _esi           ;
        mov edi, _edi           ;

        shr edi, 0x18           ;
        shr esi, 0x10           ;

        mov _esi, esi           ;
        mov _edi, edi           ;
    }

    //--------------------------------------------------------------------------

    _ebx ^= getFromConstData(0x28);
    _edx = _esi;

    __asm
    {
        mov esi, _esi;
        mov edx, _edx;

        movzx esi, dl;

        mov _esi, esi;
    }

    //--------------------------------------------------------------------------

    _esi = getFromConstData(_esi*4+0x448);
    dwordFromConstData = getFromConstData(_edi*4+0x48);

    __asm
    {
        mov esi, _esi                       ;
        add esi, dwordFromConstData         ;

        mov eax, _eax                       ;
        movzx edi, ah                       ;

        mov _edi, edi                       ;
        mov _esi, esi                       ;
    }

    //--------------------------------------------------------------------------

    _esi ^= getFromConstData(_edi*4+0x848);

    //--------------------------------------------------------------------------

    __asm
    {
        mov eax, _eax           ;
        movzx edi, al           ;

        mov _edi, edi           ;
    }

    //--------------------------------------------------------------------------

    genKeyStage3(&_esi, _edi);

    // ====================== different behavior STOP   ======================

    genKeyStage2(&_ebx, &_esi, &_edi, &_edx);
    genKeyStage3(&_esi, _edi);
    _eax ^= getFromConstData(0x2c);
    _ebx ^= getFromConstData(0x30);

    //--------------------------------------------------------------------------

    genKeyStage2(&_eax, &_esi, &_edi, &_edx);
    _eax ^= getFromConstData(0x34);
    genKeyStage3(&_esi, _edi);

    //--------------------------------------------------------------------------

    genKeyStage2(&_ebx, &_esi, &_edi, &_edx);
    genKeyStage3(&_esi, _edi);

    //--------------------------------------------------------------------------

    genKeyStage2(&_eax, &_esi, &_edi, &_edx);
    genKeyStage3(&_esi, _edi);
    _ebx ^= getFromConstData(0x38);
    _eax ^= getFromConstData(0x3c);

    //--------------------------------------------------------------------------

    genKeyStage2(&_ebx, &_esi, &_edi, &_edx);
    _ebx ^= getFromConstData(0x40);
    genKeyStage3(&_esi, _edi);

    // ====================== different behavior START  ======================

    _eax ^= _esi;
    _esi = _eax;
    _edi = _eax;

    __asm
    {
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

    //--------------------------------------------------------------------------

    // need move to edx [empty mem]
    // mov edx, empty mem

    _esi = getFromConstData(_esi*4+0x448);
    dwordFromConstData = getFromConstData(_edi*4+0x48);

    __asm
    {
        mov esi, _esi                       ;
        add esi, dwordFromConstData         ;

        mov eax, _eax                       ;
        movzx edi, ah                       ;

        mov _edi, edi                       ;
        mov _esi, esi                       ;
    }

    //--------------------------------------------------------------------------

    _esi ^= getFromConstData(_edi*4+0x848);

    //--------------------------------------------------------------------------

    __asm
    {
        mov eax, _eax           ;
        movzx edi, al           ;

        mov _edi, edi           ;
    }

    //--------------------------------------------------------------------------

    _eax ^= getFromConstData(0x44);

    //--------------------------------------------------------------------------

    std::cout << std::hex << getFromConstData(0x44) << std::endl;
    genKeyStage3(&_esi, _edi);

    // ====================== different behavior STOP   ======================


    // ======================== Stage 3   ========================

     _ecx = _eax;
     _KEY_PART.b3 = _eax & 0xff;

     __asm
     {
         mov ecx, _ecx              ;
         shr ecx, 0x18              ;

         mov _ecx, ecx              ;
     }

     //-------------------------------------------------------------------------

     _ebx ^= _esi;
     _KEY_PART.b0 = _ecx & 0xff;
     _ecx = _eax;

     __asm
     {
         mov ecx, _ecx              ;
         shr ecx, 0x10              ;

         mov _ecx, ecx              ;
     }

     //-------------------------------------------------------------------------

     _KEY_PART.b1 = _ecx & 0xff;
     _ecx = _eax;
     _eax = _ebx;

     __asm
     {
         mov eax, _eax              ;
         shr eax, 0x18              ;

         mov ecx, _ecx              ;
         shr ecx, 0x8               ;

         mov _eax, eax              ;
         mov _ecx, ecx              ;
     }

     //-------------------------------------------------------------------------

     _KEY_PART.b2 = _ecx & 0xff;
     _KEY_PART.b4 = _eax & 0xff;
     _eax = _ebx;

     __asm
     {
         mov eax, _eax              ;
         shr eax, 0x10              ;

         mov _eax, eax              ;
     }

     //-------------------------------------------------------------------------

     _KEY_PART.b7 = _ebx & 0xff;
     _KEY_PART.b5 = _eax & 0xff;
     _eax = _ebx;

     __asm
     {
         mov eax, _eax              ;
         shr eax, 0x8               ;

         mov _eax, eax              ;
     }

     //-------------------------------------------------------------------------

     _KEY_PART.b6 = _eax & 0xff;

     std::cout << std::hex << int(_KEY_PART.b0) << std::endl;
     std::cout << std::hex << int(_KEY_PART.b1) << std::endl;
     std::cout << std::hex << int(_KEY_PART.b2) << std::endl;
     std::cout << std::hex << int(_KEY_PART.b3) << std::endl;
     std::cout << std::hex << int(_KEY_PART.b4) << std::endl;
     std::cout << std::hex << int(_KEY_PART.b5) << std::endl;
     std::cout << std::hex << int(_KEY_PART.b6) << std::endl;
     std::cout << std::hex << int(_KEY_PART.b7) << std::endl;
}
