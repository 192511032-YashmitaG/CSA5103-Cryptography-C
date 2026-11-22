# EXP 11: Number of possible Playfair keys
import math
total = math.factorial(25)
power = math.log2(total)
print("Total possible keys (25!):", total)
print("Approximate power of 2: 2^{:.2f}".format(power))
