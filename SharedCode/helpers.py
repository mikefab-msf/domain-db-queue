"""
MSF-OCB Domain DB Checks (2023-11a)
**IMPORTANT**
For Internal Use Only -- NO WARRANTY! -- Risk of DATA LOSS/CORRUPTION/DISCLOSURE!!
Please first carefully read the instructions in the file "README.md" provided with this project.

Miscellaneous general-purpose static helper/utility functions
"""

from typing import Any
import random
import string


def is_invalid_param_string(arg_value: Any) -> bool:
    """
    Check if the given parameter value is <None> or not a string, or an empty or white-space-only string,
    which are all deemed invalid.

    Args:
        arg_value: the parameter value
    Returns:
        <True> if the parameter value is invalid, <False> otherwise
    """
    return arg_value is None or not isinstance(arg_value, str) or len(arg_value.strip()) <= 0


def generate_unique_identifier(length: int = 26) -> str:
    """
    Generate a unique identifier of the given length, which starts with a lower-case letter and
    is followed by a mix of lower-case letters and digits.

    Args:
        length: the length of the identifier to generate
    Returns:
        the generated unique identifier string
    """
    if length < 1:
        raise ValueError("Argument 'length' must be at least 1!")
    first_char = random.choice(string.ascii_lowercase)
    remaining_chars = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length - 1))
    unique_identifier = str(first_char + remaining_chars)
    return unique_identifier
