# Copyright (C) 2026 Cristopher Méndez Cervantes (@cristopherpydev - R3D)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# =========== GLOBAL VARIABLES ============= #
ALPHABET = 'abcdefghijklmnopqrstuvwxyz'
UC_ALPHABET = ALPHABET.upper()
SYMBOLS_ACCEPTED = '@!#?/&%*'
NUMBERS = '0123456789'

'''Generator function module that allow users to generate a configurable passwd'''

# =========== DEPENDENCIES ============= #

import random
import os
import json
import secrets

# =========== DEPENDENCIES ============= #

def generate_password(length:int=16, uppercase_letters: bool=True, numbers: bool=True, symbols: bool=False)->str:
    """#### Generates a desired password given deterministic arguments.

    Args:
        length (int, optional): The length of the password (16 by default).
        uppercase_letters (bool, optional): Optional parameter to accept uppercase letters. Defaults to True.
        lowercase_letters (bool, optional): Optional parameter to accept lowercase letters. Defaults to True.
        numbers (bool, optional): Optional parameter to accept numbers in the new password generated. Defaults to True.
        symbols (bool, optional): Optional parameter to accept symbols in the new password generated. Defaults to False.

    Returns:
        str: the password generated with the user parameters.
    """
    


    deterministic_min_numbers = random.randint(1, 3) if numbers else 0
    deterministic_min_symbols = random.randint(1, 2) if symbols else 0
    deterministic_min_uppercase = random.randint(1, 2) if uppercase_letters else 0
    
    USED = deterministic_min_uppercase + deterministic_min_numbers + deterministic_min_symbols
    generated_password = ''
    
    for _ in range((length - USED)):
        generated_password += random.choice(ALPHABET)
    
    if uppercase_letters:
        for _ in range(deterministic_min_uppercase):
            generated_password += random.choice(UC_ALPHABET)
    if numbers:
        for _ in range(deterministic_min_numbers):
            generated_password += random.choice(NUMBERS)
    if symbols:
        for _ in range(deterministic_min_symbols):
            generated_password += random.choice(SYMBOLS_ACCEPTED)
    
    generated_password = list(generated_password)
    random.shuffle(generated_password)
    return "".join(generated_password)            

def _bulk_pwd_generator(num:int, length:int, uppercase_letters:bool, numbers:bool, symbols:bool):
    """#### Hidden generator to handle bulks of passwords. 
    
    **Do not use this function by any means**.

    Args:
        num (int): The desired number of passwords that must be generated.
        length (int): The length of each password generated.
        uppercase_letters (bool): Activates uppercase letter inclussion generation on a password.
        numbers (bool): Activates number inclussion generation on a password.
        symbols (bool): Activates symbol inclussion generation on a password.

    Yields:
        _type_: _description_
    """
    for _ in range(num):
        yield generate_password(length, uppercase_letters, numbers, symbols)

def generate_bulk_pwd(num:int=10, length:int=16, uppercase_letters: bool=True, numbers: bool=True, symbols: bool=False)->list[str]:
    """_summary_

    Args:
        num (int, optional): _description_. Defaults to 10.
        length (int, optional): _description_. Defaults to 16.
        uppercase_letters (bool, optional): _description_. Defaults to True.
        numbers (bool, optional): _description_. Defaults to True.
        symbols (bool, optional): _description_. Defaults to False.

    Returns:
        list[str]: List of generated passwords (string)
    """
    return list(_bulk_pwd_generator(num, length, uppercase_letters, numbers, symbols))

def _symbolic_mnmopwd_generator(lvl, composition, NON_WORKED_FILE, CATEGORIES)->str:
    """Aux function that generates a symbolic password for an user given 4 parameters.

    Args:
        lvl (str): The complex lvl of the generated words.
        composition (str): The compositioning parameter.
        NON_WORKED_FILE (list[dict]): The data stream located in data directory as 'mnemotechnic_stream.json' file.
        CATEGORIES (list): List of filtered categories unpacked from NON_WORKED_FILE var.

    Returns:
        str: The worked password.
    """
    match composition:
        case 'standard':
            '''

            == dev maintenance guidelines == 

            standard generation states for 
            generating a sequence of two passwords with random special
            characters and numbers to improve security statements.
            
            security breaches were tested with the free online 
            [tool](https://ciberprotector.com/comprobador-de-contrase%C3%B1as/)
            
            '''
            
            COMPLEXITY = 2
            GENERATED_CATEGORIES = [random.choice(CATEGORIES) for _ in range(COMPLEXITY)]
            PLAINED_DATASET = []
            PASSWORD = ''

            for category in GENERATED_CATEGORIES:
                for data in NON_WORKED_FILE:
                    if data['category'] == category:
                        PLAINED_DATASET.append(data['content'][lvl])
                            
            for i in range(len(PLAINED_DATASET)):
                SYMBOL = random.choice(SYMBOLS_ACCEPTED)
                NUMBER = random.choice(NUMBERS)
                if i!= len(PLAINED_DATASET)-1:
                    PASSWORD+= NUMBER + SYMBOL + (random.choice(PLAINED_DATASET[i]) + "_")
                else:
                    PASSWORD+=NUMBER + SYMBOL + (random.choice(PLAINED_DATASET[i]))
            return PASSWORD
        case 'complex':
            '''

            == dev maintenance guidelines == 

            complex generation states for 
            generating a sequence of 3-4 passwords with random special
            characters and numbers to improve security statements.
            
            security breaches were tested with the free online 
            [tool](https://ciberprotector.com/comprobador-de-contrase%C3%B1as/)
            
            '''
            COMPLEXITY = random.randint(3,4)
            GENERATED_CATEGORIES = [random.choice(CATEGORIES) for _ in range(COMPLEXITY)]
            PLAINED_DATASET = []
            PASSWORD = ''

            for category in GENERATED_CATEGORIES:
                for data in NON_WORKED_FILE:
                    if data['category'] == category:
                        PLAINED_DATASET.append(data['content'][lvl])
                    
            
            for i in range(len(PLAINED_DATASET)):
                SYMBOL = random.choice(SYMBOLS_ACCEPTED)
                NUMBER = random.choice(NUMBERS)
                if i!= len(PLAINED_DATASET)-1:
                    PASSWORD+= NUMBER + SYMBOL + (random.choice(PLAINED_DATASET[i]) + "_")
                else:
                    PASSWORD+=NUMBER + SYMBOL + (random.choice(PLAINED_DATASET[i]))
            return PASSWORD

def generate_symbolic_mnemopwd(lvl:str="easy", composition:str="standard")->str:
    """#### Generates a mnemotechnic password for the user given an optional ``lvl`` parameter and ``composition``.

    Available options are:
    * lvl
        * easy
        * medium
        * hard
    * composition
        * standard
        * complex

    Args:
        lvl (str, optional): The complexity level of the generated words. Defaults to "easy".
        composition (str, optional): The composition of the generated string. Defaults to "standard".
    Returns:
        str: The worked password.
    """
    BASE_PATH = os.path.dirname(os.path.abspath(__file__))
    PATH_TO_STREAM = os.path.join(BASE_PATH, 'data', 'mnemotechnic_stream.json')
    NON_WORKED_FILE = ""
    with open(PATH_TO_STREAM, 'r') as f:
        file = json.load(f)
        NON_WORKED_FILE = file
    
    if NON_WORKED_FILE:
        CATEGORIES = [NON_WORKED_FILE[i]['category'] for i in range(len(NON_WORKED_FILE))]
        pwd = _symbolic_mnmopwd_generator(lvl, composition, NON_WORKED_FILE, CATEGORIES)
        return pwd
    else:
        raise("There has been an error generating a symbolic password.")

def generate_pin(length:int=4)->str:
    """_summary_

    Args:
        length (int, optional): The size of the random generated serie. Defaults to 4.

    Returns:
        str: A serie of random generated numbers.
    """
    return "".join([random.choice(NUMBERS) for _ in range(length)])

def generate_token(bytes:int=16)->str:
    """_summary_

    Args:
        bytes (int, optional): the bytes accepted. Defaults to 16.

    Returns:
        str: _description_
    """
    return str(secrets.token_hex(bytes))

