import pytest

from secgen.analysis import (
    _estimate_crack_time,
    analyze_one,
    analyze_many,
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_BLUE,
    COLOR_RED,
    COLOR_RESET
)

@pytest.mark.parametrize("entropy_bits, expected_time_format", [
    (10, "Instant (< 1 s)"),               # 2^10 / 100B < 1s
    (38, "3 s"),                           # 2^38 / 100B ≈ 2.74s -> 3s
    (45, "6 min"),                         # 2^45 / 100B ≈ 351s -> ~6 min
    (50, "3 h"),                           # 2^50 / 100B ≈ 11258s -> ~3 h
    (60, "133 days"),                      # 2^60 / 100B ≈ 11529215s -> ~133 days
    (65, "12 years"),                      # 2^65 / 100B ≈ 3.68e8s -> ~12 years
    (72, "15 centuries"),                  # 2^72 / 100B ≈ 4.72e10s -> ~15 centuries
    (100, "Millenia (Imposible with the actual technology)")
])
def test_estimate_crack_time(entropy_bits, expected_time_format):
    """Checks if the estimated crack time correctly matches the expected format for various entropy bit levels."""
    assert _estimate_crack_time(entropy_bits) == expected_time_format

def test_analyze_one_weak_password():
    """Checks if a short, simple password is appropriately classified as 'Weak'."""
    result = analyze_one("abc")
    assert result['crack_time'] is not None
    assert COLOR_RED in result['feedback']
    assert "Weak" in result['feedback']

def test_analyze_one_average_password():
    """Checks if a medium-length alphanumeric password is classified as 'Average' or 'Strong'."""
    result = analyze_one("Contrasena123")
    assert COLOR_YELLOW in result['feedback'] or COLOR_BLUE in result['feedback']
    assert "Average" in result['feedback'] or "Strong" in result['feedback']

def test_analyze_one_excellent_password():
    """Checks if a long, complex password with symbols and mixed casing is classified as 'Excellent'."""
    result = analyze_one("SuperS3cr3t@P@ssw0rd!!")
    assert COLOR_GREEN in result['feedback']
    assert "Excellent" in result['feedback']

def test_analyze_one_without_crack_time():
    """Checks that the crack time is set to None when the crack_time parameter is explicitly False."""
    result = analyze_one("TestPass123!", crack_time=False)
    assert result['crack_time'] is None

def test_analyze_one_exception_handling():
    """Checks that an empty password gracefully handles math exceptions and returns the expected error feedback."""
    result = analyze_one("")
    assert "There was an error during analysis handling" in result['feedback']
    assert result.get('crack_time', None) == ''

def test_analyze_many_basic():
    """Checks the bulk analysis of multiple passwords, ensuring different complexities are evaluated correctly."""
    passwords = ["123", "Admin123!", "VeryLongAndComplexPassw0rd@!"]
    results = analyze_many(passwords)
    
    assert len(results) == 3
    assert isinstance(results, list)
    assert isinstance(results[0], dict)
    assert COLOR_RED in results[0]['feedback']
    assert COLOR_GREEN in results[2]['feedback']

def test_analyze_many_no_crack_time():
    """Checks that bulk analysis respects the crack_time parameter set to False across all generated feedbacks."""
    passwords = ["test1", "test2"]
    results = analyze_many(passwords, crack_time=False)
    
    for res in results:
        assert res['crack_time'] is None