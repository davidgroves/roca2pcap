"""A script that will be installed with your package"""

import sys

import python_vscode_template2.arithmetic


def main():
    """The main function of the script."""
    print("I'm a simple demo script !")
    print(python_vscode_template2.arithmetic.add_ints(int(sys.argv[1]), int(sys.argv[2])))


if __name__ == "__main__":
    main()
