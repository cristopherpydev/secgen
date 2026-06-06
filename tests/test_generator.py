import pytest
from secgen import generate_passphrase, generate_mnemonic_password, generate_many_passphrases, generate_many_passwords, generate_pin, generate_token, generate_password
from unittest.mock import patch, mock_open
def test_generate_pin_default_length():
    """Checks if the pin is a 4 numeric character string."""
    pin = generate_pin()
    assert len(pin) == 4
    assert pin.isdigit()

def test_generate_pin_below_or_equal_to_zero():
    length = 0
    length_1 = -1
    with pytest.raises(ValueError):
        generate_pin(length=length)

    with pytest.raises(ValueError):
        generate_pin(length=length_1)
        
def test_generate_pin_custom_length():
    """Checks if the pin has the desired length."""
    desired_length = 16
    pin = generate_pin(length=desired_length)
    assert len(pin) == desired_length
    assert pin.isdigit()

def test_generate_token_default():
    """Checks if default 16 bytes generate a 32 char hex string."""
    token = generate_token()
    assert len(token) == 32

def test_generate_token_custom_length():
    """Checks if custom 32 bytes generate a 64 char hex string."""
    token = generate_token(bytes=32)
    assert len(token) == 64

def test_generate_pin_invalid_type():
    """Checks that passing a string as length raises a TypeError."""
    
    invalid_length = "four"
    
    #assert block
    with pytest.raises(TypeError):
        generate_pin(length=invalid_length)

def test_generate_password_default():
    """Checks if a default generation has the minimum accepted"""
    password = generate_password()
    assert len(password) == 16
    assert any(p.isdigit() for p in password)
    assert any(p.isupper() for p in password)

def test_generate_password_custom_length():
    """Checks if a default generation has the minimum accepted"""
    desired_length = 18
    password = generate_password(length=desired_length)
    assert len(password) == desired_length
    assert any(p.isdigit() for p in password)
    assert any(p.isupper() for p in password)

@pytest.mark.parametrize("length, uppercase_letters, numbers, symbols", [
    (8, True, False, False),  
    (16, True, True, False),   
    (32, True, True, True),   
    (64, False, False, False)  
])
def test_generate_password_combinations(length, uppercase_letters, numbers, symbols):
    """Checks that the generated password respects the requested ruleset."""
    
    password = generate_password(length=length, uppercase_letters=uppercase_letters, numbers=numbers, symbols=symbols)
    
    assert len(password) == length    
    if uppercase_letters:
        assert any(c.isupper() for c in password)
    else:
        assert not any(c.isupper() for c in password)
    if numbers:
        assert any(c.isdigit() for c in password)
    else:
        assert not any(c.isdigit() for c in password)

def test_generate_token_invalid_bytes():
    with pytest.raises(ValueError):
        generate_token(bytes=10)

def test_generate_many_passwords_expected_length():
    '''Checks if the massive generation actually generates the expected amount of
    passwords.'''
    
    expected_amount = 10
    passwords = generate_many_passwords(num=expected_amount)
    assert len(passwords) == expected_amount

def test_generate_many_passwords_each_password_has_same_length():
    '''Checks if the massive generation actually generates a patron of same size for each word.'''
    password_length = 12
    passwords = generate_many_passwords(length=password_length)
    assert all(len(p) == password_length for p in passwords)

def test_generate_many_passwords_expected_length_and_amount():
    password_length = 12
    expected_amount = 5
    passwords = generate_many_passwords(num=expected_amount, length=password_length)
    
    assert len(passwords) == expected_amount
    assert all(len(p) == password_length for p in passwords)

def test_generate_many_passwords_passwords_is_zero_or_below():
    '''Checks if the amount of passwords is zero or below and if the raise blockcode returns an error.'''
    amount = 0
    second_amount = -1
    with pytest.raises(ValueError):
        generate_many_passwords(num=amount)

    with pytest.raises(ValueError):
        generate_many_passwords(num=second_amount)    

def test_generate_passphrase_invalid_separator_empty():
    """Checks that an empty separator returns the expected error string."""
    result = generate_passphrase(separator="")
    assert result == "A separator must be set."

def test_generate_passphrase_invalid_separator_type():
    """Checks that a non-string separator returns the expected error string."""
    result = generate_passphrase(separator=123)
    assert result == "The separator must be a string character."

def test_generate_passphrase_invalid_words_negative():
    """Checks that requesting 0 or negative words returns the expected error string."""
    result = generate_passphrase(words=-2)
    assert result == "Words parameter must be above 0."

@patch('builtins.open', new_callable=mock_open, read_data="apple\nbanana\ncherry\ndate\nelephant")
def test_generate_passphrase_default_execution(mock_file):
    """Checks if default passphrase generates a string with the default '-' separator."""
    passphrase = generate_passphrase()
    
    assert isinstance(passphrase, str)
    assert "-" in passphrase
    assert passphrase.count("-") == 3  

@patch('builtins.open', new_callable=mock_open, read_data="apple\nbanana\ncherry\ndate\nelephant")
def test_generate_many_passphrases_amount(mock_file):
    """Checks the bulk generation of passphrases."""
    expected_amount = 5
    passphrases = generate_many_passphrases(number=expected_amount)
    
    assert len(passphrases) == expected_amount
    assert isinstance(passphrases, list)

def test_generate_mnemonic_password_standard():
    """Checks standard composition execution."""
    pwd = generate_mnemonic_password(lvl="easy", composition="standard")
    assert isinstance(pwd, str)
    assert len(pwd) > 0

def test_generate_many_passphrases_number_below_zero():
    number = 0
    number_2 = -1
    with pytest.raises('ValueError'):
        generate_many_passphrases(number=number)
    
    with pytest.raises('ValueError'):
        generate_many_passphrases(number=number_2)

def test_generate_mnemonic_password_complex():
    """Checks complex composition execution."""
    pwd = generate_mnemonic_password(lvl="hard", composition="complex")
    assert isinstance(pwd, str)
    assert len(pwd) > 0

