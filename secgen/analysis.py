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
'''analysis and reports'''

# =========== GLOBAL VARIABLES ============= #

COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_RED = "\033[91m"
COLOR_RESET = "\033[0m"
SYMBOLS_ACCEPTED = '@!#?/&%*'

# =========== DEPENDENCIES ============= #

import math

def _estimate_crack_time(entropy_bits: float, hashes_per_sec: int = 100_000_000_000) -> str:
    """Hidden function that calculates the estimated crack time of a given password

    Args:
        entropy_bits (float): Given entropy bits for the calculation.
        hashes_per_sec (int, optional): Hashes per second. Defaults to 100_000_000_000.

    Returns:
        str: The stimated crack time to unveil a password via brute force attacks.
    """
    
    #(Overflow fallback)
    #  
    # entropy of more than 256 bytes generates an absurd large numb so we need to handle it.
    if entropy_bits >= 256:
        return "Uncalculable (Deeper than the Big Bang theory)"

    #  T = (2^E) / H

    combinations = 2 ** entropy_bits
    seconds = combinations / hashes_per_sec

    if seconds < 1:
        return "Instant (< 1 s)"
    elif seconds < 60:
        return f"{round(seconds)} s"
    elif seconds < 3600:
        return f"{round(seconds / 60)} min"
    elif seconds < 86400:
        return f"{round(seconds / 3600)} h"
    elif seconds < 31536000:
        return f"{round(seconds / 86400)} days"
    elif seconds < 3153600000: 
        return f"{round(seconds / 31536000)} years"
    elif seconds < 3153600000000:
        return f"{round(seconds / 3153600000)} centuries"
    else:
        return "Millenia (Imposible with the actual technology)"
    
def analyze_one(password:str, crack_time:bool=True)-> dict:
    """Analizes a given password returning a feedback about the security
    based on cybersecurity facts and statements.

    Args:
        password (str): The given password.
        crack_time (bool, optional): Time that a cracker needs to unveil the password. Defaults to True.

    Returns:
        dict: The dataset with the information.
    """
    DATASET = {
        'feedback': '',
        'crack_time': ''
    }
    POOL_SCORE = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_numbers = any(c.isdigit() for c in password)
    has_symbols = any(c in SYMBOLS_ACCEPTED for c in password)

    POOL_SCORE += 26 if has_lower else 0
    POOL_SCORE += 26 if has_upper else 0
    POOL_SCORE += 10 if has_numbers else 0
    POOL_SCORE += 32 if has_symbols else 0

    if not password:
        raise ValueError("Error. A password must be given.")

    try:
        STRENGTH = round(len(password) * math.log2(POOL_SCORE))

        if not has_numbers:
            STRENGTH -= (STRENGTH * 0.1)
        if not has_symbols:
            STRENGTH -= (STRENGTH * 0.1)

        STRENGTH = round(STRENGTH, 2)
        time = _estimate_crack_time(STRENGTH)

    except Exception as e:
        DATASET['feedback'] = f"There was an error during analysis handling: {e}"
        return DATASET
    

    DATASET['crack_time'] = time if crack_time else None

    if STRENGTH < 60:
        DATASET['feedback'] = f"{COLOR_RED}Weak{COLOR_RESET}"
        
    elif 60 <= STRENGTH < 80:
        DATASET['feedback'] = f"{COLOR_YELLOW}Average{COLOR_RESET}"

    elif 80 <= STRENGTH < 100:
        DATASET['feedback'] = f"{COLOR_BLUE}Strong{COLOR_RESET}"

    else:
        DATASET['feedback'] = f"{COLOR_GREEN}Excellent{COLOR_RESET}"

    return DATASET

def analyze_many(password_bulk:list[str], crack_time:bool=True)->list[dict]:
    """Analizes a list of passwords, generating a list of dictionaries with
    the result of each of them. 

    Args:
        password_bulk (list[str]): The bulk (list) of passwords.
        crack_time (bool, optional): Enables the crack time information in the report. Defaults to True.

    Returns:
        list[dict]: The "report" dataset.
    """
    if not password_bulk:
        raise ValueError("Error, a password bulk must be set.")

    DATASET_BULK = [analyze_one(pwd, crack_time) for pwd in password_bulk]
    return DATASET_BULK    

