'''

Script to generate passwords with 8 minimum mixed caracters

usage: generate_randown_passwords.py [-h] length

Generate a random password of specified length.

positional arguments:
  length      'Length' of the password to be generated.

options:
  -h, --help  show this help message and exit

python generate_randown_passwords.py N (N = number of caracters)

'''

import string
import random
import argparse

def random_passwd(length):
    if length < 8:
        raise ValueError("Password length should be at least 8 characters")

    secure_random = random.SystemRandom()

    all_characters = string.ascii_letters + string.digits + string.punctuation

    # select 2 lowercase, 2 uppercase, 2 digit, and 2 special char
    password = [
        secure_random.choice(string.ascii_lowercase),
        secure_random.choice(string.ascii_uppercase),
        secure_random.choice(string.digits),
        secure_random.choice(string.punctuation),
        secure_random.choice(string.ascii_lowercase),
        secure_random.choice(string.ascii_uppercase),
        secure_random.choice(string.digits),
        secure_random.choice(string.punctuation),
    ]

    # generate other characters
    password.extend(secure_random.choice(all_characters) for _ in range(length -8))

    secure_random.shuffle(password)

    return f'senha: {"".join(password)}'

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a random password of specified length.")
    parser.add_argument("length", type=int, help="'Length' of the password to be generated.")
    args = parser.parse_args()

    try:
        print(random_passwd(args.length))
    except ValueError as e:
        print(e)
