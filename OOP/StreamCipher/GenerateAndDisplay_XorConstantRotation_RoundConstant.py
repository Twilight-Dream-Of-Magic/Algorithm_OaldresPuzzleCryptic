import numpy as np
from mpmath import mp

# Set the desired decimal precision
mp.dps = 100

# Define the mathematical constants
e = mp.e
pi = mp.pi
phi = (1 + mp.sqrt(5)) / 2
sqrt_2 = mp.sqrt(2)
sqrt_3 = mp.sqrt(3)
gamma = mp.mpf("0.5772156649") # Euler–Mascheroni constant
delta = mp.mpf("4.6692016091") # Feigenbaum constant
rho = mp.mpf("1.3247179572") # Plastic number

'''
e = mp.e
pi = mp.pi
phi = (1 + mp.sqrt(5)) / 2
sqrt_2 = mp.sqrt(2)
sqrt_3 = mp.sqrt(3)
gamma = mp.euler  # Eulerâ€“Mascheroni constant
delta = mp.mpf('4.669201609102990671853203820466')  # Feigenbaum constant delta
rho = mp.cbrt((9 + mp.sqrt(69)) / 18) + mp.cbrt((9 - mp.sqrt(69)) / 18) # Plastic number
'''

print(str(e) + '\n')
print(str(pi) + '\n')
print(str(phi) + '\n')
print(str(sqrt_2) + '\n')
print(str(sqrt_3) + '\n')
print(str(gamma) + '\n')
print(str(delta) + '\n')
print(str(rho) + '\n')

def f(x):
    x = mp.mpf(x)
    term1 = (e ** x - mp.cos(pi * x))
    term2 = (phi * x ** 2 - phi * x - 1)
    term3 = (x * sqrt_2 - mp.floor(x * sqrt_2))
    term4 = (x * sqrt_3 - mp.floor(x * sqrt_3))
    term5 = mp.log(1 + x)
    term6 = (x * delta - mp.floor(x * delta))
    term7 = (x * rho - mp.floor(x * rho))

    return term1 * term2 * term3 * term4 * term5 * term6 * term7

def print_console():
    round = 1

    binary_string = ""

    for index in range(150):
        # Calculate the result for a given input value
        result = f(round)

        print("Round: ", index)

        # Print the decimal result
        print("Decimal number:", result)

        # Convert the fractional part to binary and print it
        fractional_part = result - mp.floor(result)
        binary_fractional_part = format(int(fractional_part * 2**128), 'b')  # Using 128 bits of precision for the binary representation
        # print("Binary representation of fractional part:", binary_fractional_part)

        # Convert the fractional part to hexadecimal and print it
        hexadecimal_fractional_part = format(int(fractional_part * 2**128), 'x')
        print("Hexadecimal representation of fractional part:", hexadecimal_fractional_part)

        # Print the integer part
        integer_part = int(result)
        print("Integer part:", integer_part)

        round += 1
        binary_string += (binary_fractional_part)

    print("Binary String: ", binary_string)
    # Convert the binary string to an integer
    integer_value = int(binary_string, 2)

    # Convert the integer to a hexadecimal string
    hexadecimal_string = format(integer_value, 'x')

    print("Hexadecimal representation:", hexadecimal_string)

    grouped_hexadecimal_string = ','.join([hexadecimal_string[i:i+16] for i in range(0, len(hexadecimal_string), 16)])
    print("Grouped Hexadecimal representation:", grouped_hexadecimal_string)

print_console()