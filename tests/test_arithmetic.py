"""Test Arithmetic Module"""

import python_vscode_template2.arithmetic


def test_add():
    assert python_vscode_template2.arithmetic.add_ints(2, 2) == 4


def test_add_negatives():
    assert python_vscode_template2.arithmetic.add_ints(-2, 2) == 0

