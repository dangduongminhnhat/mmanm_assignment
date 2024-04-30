from rsa_implement import RSA
import time

print_str = """
                ----------------------------------
                *  *  *       * *  *         *
                *     *      *              * *
                *  * *          *          * * *
                *     *            *      *     *
                *      *     *  * *      *       *
                -----------------------------------
                    Welcome to our RSA system!!!
----------------------------------------------------------------------------------------------------
    0. Exit
    1. Find a large prime number given the desired number of bits for the prime.
    2. Calculate the greatest common divisor (GCD) of two large integers.
    3. Compute the decryption key d given the encryption key e and two large prime numbers p and q.
    4. Generate a random key pair given two large prime numbers p and q.
    5. Encrypt a message (in number) given the message and the encryption key e and n.
    6. Decrypt a ciphertext (in number) given the encrypted message and the decryption key d and n.
    7. Encrypt a message (in string) given the message and the encryption key e and n.
    8. Decrypt a ciphertext (in string) given the encrypted message and the decryption key d and n.
    9. Generate d and e randomly with your input as Key bit length.
-----------------------------------------------------------------------------------------------------
"""

my_rsa = RSA()
while True:
    print(print_str)
    num = input("Choose your option >: ")
    if num == "0":
        print("Thank you, bye!")
        break
    elif num == "1":
        nbits = int(
            input("Enter the large prime number's bit you want to find >: "))
        start = time.time()
        prime = my_rsa.getPrime(nbits)
        end = time.time()
        print(f">> The large prime number with {nbits} bits is {prime}.")
        print(f">> Time to execute is {end - start} seconds.")
    elif num == "2":
        number_1 = int(input("Enter the first big integer number >: "))
        number_2 = int(input("Enter the second big integer number >: "))
        start = time.time()
        gcd1 = my_rsa.GCD(number_1, number_2)
        end = time.time()
        print(f">> The GCD found by Euclid's algorithm is {gcd1}")
        print(f">> Time to execute is {end - start} seconds.")
        start = time.time()
        gcd1 = my_rsa.gcd(number_1, number_2)
        end = time.time()
        print(f">> The GCD found by Stein's algorithm is {gcd1}")
        print(f">> Time to execute is {end - start} seconds.")
    elif num == "3":
        e = int(input("Enter the encryption key e >: "))
        p = int(input("Enter the first large prime number p >: "))
        q = int(input("Enter the first large prime number q >: "))
        my_rsa.e = e
        my_rsa.p = p
        my_rsa.q = q
        start = time.time()
        my_rsa.n_and_phi_generate()
        my_rsa.d_generate()
        end = time.time()
        print(f">> The decryption key d is {my_rsa.d}.")
        print(f">> Time to execute is {end - start} seconds.")
    elif num == "4":
        p = int(input("Enter the first large prime number p >: "))
        q = int(input("Enter the first large prime number q >: "))
        my_rsa.p = p
        my_rsa.q = q
        start = time.time()
        my_rsa.n_and_phi_generate()
        my_rsa.e_generate()
        my_rsa.d_generate()
        end = time.time()
        print(f">> The encryption key e is {my_rsa.e}.")
        print(f">> The size of e is {my_rsa.size(my_rsa.e)} bits.")
        print(f">> The modulus n is {my_rsa.n}.")
        print(f">> The decryption key d is {my_rsa.d}.")
        print(f">> Time to execute is {end - start} seconds.")
    elif num == "5":
        e = int(input("Enter the encryption key e >: "))
        n = int(input("Enter the modulus n >: "))
        message = int(input("Enter your message (in number) to encrypt >: "))
        my_rsa.e = e
        my_rsa.n = n
        start = time.time()
        ciphertext = my_rsa.encrypt(message)
        end = time.time()
        print(f">> The encrypted ciphertext (in number) is {ciphertext}.")
        print(
            f">> The encrypted ciphertext (in bytes) is {my_rsa.long_to_bytes(ciphertext)}.")
        print(f">> Time to execute is {end - start} seconds.")
    elif num == "6":
        d = int(input("Enter the decryption key d >: "))
        n = int(input("Enter the modulus n >: "))
        ciphertext = int(
            input("Enter your ciphertext (in number) to decrypt >: "))
        my_rsa.d = d
        my_rsa.n = n
        start = time.time()
        message = my_rsa.decrypt(ciphertext)
        end = time.time()
        print(f">> The message (in number) is {message}.")
        print(f">> The message (in bytes) is {my_rsa.long_to_bytes(message)}.")
        print(f">> Time to execute is {end - start} seconds.")
    elif num == "7":
        e = int(input("Enter the encryption key e >: "))
        n = int(input("Enter the modulus n >: "))
        message = input("Enter your message (in string) to encrypt >: ")
        my_rsa.e = e
        my_rsa.n = n
        start = time.time()
        ciphertext = my_rsa.encrypt_plaintext(message)
        end = time.time()
        print(f">> The encrypted ciphertext (in bytes) is {ciphertext}.")
        print(
            f">> The encrypted ciphertext (in number) is {my_rsa.bytes_to_long(ciphertext)}.")
        print(f">> Time to execute is {end - start} seconds.")
    elif num == "8":
        d = int(input("Enter the decryption key d >: "))
        n = int(input("Enter the modulus n >: "))
        ciphertext = input("Enter your ciphertext (in string) to decrypt >: ")
        my_rsa.d = d
        my_rsa.n = n
        start = time.time()
        message = my_rsa.decrypt_ciphertext(ciphertext)
        end = time.time()
        print(f">> The message (in bytes) is {message}.")
        print(
            f">> The message (in number) is {my_rsa.bytes_to_long(message)}.")
        print(f">> Time to execute is {end - start} seconds.")
    elif num == "9":
        keybits = int(input("Enter the number of key's bits >: "))
        my_rsa.key_bits = keybits
        start = time.time()
        my_rsa.p_and_q_generate()
        my_rsa.e_generate()
        my_rsa.d_generate()
        end = time.time()
        print(f">> The first prime p is {my_rsa.p}")
        print(f">> The size of p is {my_rsa.size(my_rsa.p)} bits.")
        print(f">> The second prime q is {my_rsa.q}")
        print(f">> The size of q is {my_rsa.size(my_rsa.q)} bits.")
        print(f">> The encryption key e is {my_rsa.e}.")
        print(f">> The size of e is {my_rsa.size(my_rsa.e)} bits.")
        print(f">> The modulus n is {my_rsa.n}.")
        print(f">> The decryption key d is {my_rsa.d}.")
        print(f">> Time to execute is {end - start} seconds.")
    else:
        print(">> Wrong option, please choose option again.")
    print("-------------------------------------------------------------------------------------")
    input("Press Enter to continue.")
