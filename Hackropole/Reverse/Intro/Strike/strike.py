to_check = "# congratulations! this is a strike :-) you should now see the flag printed ... #"
charset = "abcdefghijklmnopqrstuvwxyz!# $:-()."

# For the flag
flag = ''

def base16_inverse(byte_val):
    """
    Convertit un entier (0-255) en deux caractères hexadécimaux.
    Inverse de la fonction base16(a1, a2).
    """
    if not (0 <= byte_val <= 255):
        raise ValueError("L'entrée doit être un entier entre 0 et 255.")

    # Sépare les 4 bits de poids fort et de poids faible
    high_nibble = (byte_val >> 4) & 0xF
    low_nibble = byte_val & 0xF

    # Convertit en caractère hexadécimal
    a1 = format(high_nibble, 'x')
    a2 = format(low_nibble, 'x')
    return a1, a2


for i in range(0, 162, 2):
    for j in range(0, 35):
        if to_check[i // 2] == charset[(i + j) % 35]:
            str1, str2 = base16_inverse(j)
            flag += str1 + str2

print(flag)
