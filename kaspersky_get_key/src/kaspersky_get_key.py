
#### get array of symbols
const_str = "Q38B7[JPX4p$A`b]Em2/V@%c)Nl6GroRque+UhCsSid5j'>;^1(O=!LK\\I\"F*Y9,<T.WZ_&t?fDMan:#-k0Hg"
enum_arr = {}
count = 0
for x in const_str:
    enum_arr[x] = count
    count += 1


### get array of possible numbers
dividend = list(range(0x1, 0x100))
divisor = 0x55
numbers = {}

for x in dividend:
    remainder = x % divisor
    if remainder in numbers:
        numbers[remainder].append(int(x))
    else:
        temp = []
        temp.append(int(x))
        numbers[remainder] = temp

### get encrypted data
enc_file = open('rprotected.dat')
dec_file = open("protected_key.dat", "wb") 

flag = 0
while True:
    byte_5 = []
    for i in range(5):
        sym = enc_file.read(1)
        if sym == '':
            flag = 1
            break
        byte_5.append(sym)

    if flag:
        break
    
    _dividend = 0
    for x in byte_5:
        reminder = enum_arr[x]
        _dividend = _dividend * divisor + reminder

    b_arr = bytearray()
    b0 = _dividend & 0xff   
    b1 = (_dividend >> 8) & 0xff  
    b2 = (_dividend >> 16) & 0xff  
    b3 = (_dividend >> 24) & 0xff
    b_arr.append(b3)
    b_arr.append(b2)
    b_arr.append(b1)
    b_arr.append(b0)
    dec_file.write(b_arr)


enc_file.close()
dec_file.close()




    
    
