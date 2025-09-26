import numpy as np
from mpmath import mp

# Set the desired decimal precision
# Precision (must stay 100)
mp.dps = 100

def plastic_number():
    """
    Compute the Plastic number (real root of x^3 = x + 1)
    with dps digits of precision.
    Returns the high-precision value as an mp.mpf.
    """
    # Use the closed-form algebraic expression
    num = ( (9 - mp.sqrt(69))**(1/mp.mpf(3)) +
            (9 + mp.sqrt(69))**(1/mp.mpf(3)) )
    den = (2**(1/mp.mpf(3))) * (3**(2/mp.mpf(3)))
    return num / den

# Constants (high precision)
e = mp.e
pi = mp.pi
phi = (1 + mp.sqrt(5)) / 2
sqrt_2 = mp.sqrt(2)
sqrt_3 = mp.sqrt(3)
gamma = mp.euler
delta = mp.mpf("4.6692016091029906718532038204662016172581855774757686327456513430041343134300413413343302113134731373868974402393480138")
rho = plastic_number()

print(str(e) + '\n')
print(str(pi) + '\n')
print(str(phi) + '\n')
print(str(sqrt_2) + '\n')
print(str(sqrt_3) + '\n')
print(str(gamma) + '\n')
print(str(delta) + '\n')
print(str(rho) + '\n')

def frac(x):
    return x - mp.floor(x)

# V2 polynomial Weyl with all high-precision constants
def f(n):
    n = mp.mpf(n)
    x = mp.mpf("0")
    x = frac(x + e      *  n      )  # n^1
    x = frac(x + pi     *  n**2   )  # n^2
    x = frac(x + phi    *  n**3   )  # n^3
    x = frac(x + sqrt_2 *  n**4   )  # n^4
    x = frac(x + sqrt_3 *  n**5   )  # n^5
    x = frac(x + gamma  *  n**6   )  # n^6
    x = frac(x + delta  *  n**7   )  # n^7
    x = frac(x + rho    *  n**8   )  # n^8
    return x

# Old Version with all high-precision constants
'''
e = mp.e
pi = mp.pi
phi = (1 + mp.sqrt(5)) / 2
sqrt_2 = mp.sqrt(2)
sqrt_3 = mp.sqrt(3)
gamma = mp.euler  # Eulerâ€“Mascheroni constant
delta = mp.mpf('4.669201609102990671853203820466')  # Feigenbaum constant delta
rho = mp.cbrt((9 + mp.sqrt(69)) / 18) + mp.cbrt((9 - mp.sqrt(69)) / 18) # Plastic number

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
'''

assert mp.dps == 100, "mp.dps MUST be 100 decimal (N * 10^{-100}) for bit-exact reproduction"

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