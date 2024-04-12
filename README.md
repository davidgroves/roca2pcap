# Overview

This is a highly opininated guide on how to setup VScode for Python Development the way I personally like it, with a baseline Python project the way I also like it.

This doesn't mean I am correct, or someone with other preferences is incorrect, but this is what works for me.

Note this only works for pure Python projects. If your project requires C extensions or rust code, you will need to replace the flit builder with one that supports those things.

## What is included in this skeleton

1. My vscode setup for Python, including what plugins I use (in `.vscode/settings.json`)
1. Examples for automated formatting with [ruff](https://black.readthedocs.io/en/stable/) and [isort](https://pycqa.github.io/isort/).
1. Examples for automated testing with [pytest](https://docs.pytest.org/).
1. Examples for automatically testing the documentation examples with pytest.
1. Examples for automated documentation building with [mkdocs](https://www.mkdocs.org/)
1. Examples for automatic linting with [pylint](https://pypi.org/project/pylint/)
1. Examples for automatic type checking with [mypy](https://mypy.readthedocs.io/en/stable/)
1. Examples for automatic testing in multiple environments with [tox](https://tox.wiki/)
1. Examples for [Github Actions](https://github.com/features/actions) automation for running your tox test suite.

## Software you need

Make sure the following applications are installed on your system globally. How you do this obviously varies depending on if you are using Windows, OSX or Linux.

- [Python3](https://www.python.org/), at least 3.10.
- [Git](https://git-scm.com/)
- [Visual Studio Code](https://code.visualstudio.com/)
- [uv](https://astral.sh/blog/uv) (installed outside project)

Note on Debian/Ubuntu based distributions, you will need to `apt-get install python3 python3-pip python3-venv git code`.

## How to setup

- Copy the contents of this git repo to your new project directory, or use the [Github Templates](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template) feature to make a copy of this.
- Make a venv with `uv venv -p 3.12 .venv`. (change the python version if you need to)
- Acivate the virtualenv as it advises, with `source .venv/bin/activate`.
- Update the `LICENSE` file with your appropriate license information.
- Replace this `README.md` file with an appropriate readme file.

You then need to install the development dependancies, and then the package in installable mode.

```console
uv pip install -r requirements-dev.txt
flit install
```

## My developer workflow

1. Use vscode tools while developing, running tests out of vscode.
1. View the "problems" tab.
1. When ready to commit, I run `tox` from the command line.
1. If `tox` returns no errors, I can commit and push.
1. I can then verify github actions produces no errors on that push.  

### Use the package. It is fully installed and usable

```console
$ python
>>> import python_vscode_template.arithmetic as ar
>>> ar.add_ints(2,3)
5
```

### Format it with the [black](https://black.readthedocs.io/en/stable/) formatter

```console
$ black .
All done! ✨ 🍰 ✨
6 files left unchanged.
```

### Correct the import order with [isort](https://pycqa.github.io/isort/)

```console
$ isort .
Skipped 5 files
```

### Run the tests (from the commmand line)

```console
$ pytest
======================================= test session starts ========================================
platform linux -- Python 3.11.4, pytest-7.4.0, pluggy-1.2.0
rootdir: /home/dwg/CODE/Python-VSCode-Template
configfile: pyproject.toml
testpaths: tests
plugins: asyncio-0.21.1, anyio-3.7.1, cov-4.1.0
asyncio: mode=Mode.STRICT
collected 5 items                                                                                  

tests/test_arithmetic.py ....                                                                [ 80%]
tests/test_pokemon.py .                                                                      [100%]

======================================== 5 passed in 0.27s =========================================
```

### Verify the documentation tests (from the command line)

```console
$ pytest --doctest-modules src/
====================================== test session starts ======================================
platform linux -- Python 3.11.4, pytest-7.4.0, pluggy-1.2.0
rootdir: /home/dwg/CODE/Python-VSCode-Template
configfile: pyproject.toml
plugins: asyncio-0.21.1, anyio-3.7.1, cov-4.1.0
asyncio: mode=Mode.STRICT
collected 1 item                                                                                                                      

src/python_vscode_template2/arithmetic.py .                                                [100%]                                          
====================================== 1 passed in 0.03s =======================================
```

### Verify the type checking

```console
$ mypy src/
Success: no issues found in 4 source files
```

### Build the documentation and place the results in `site/`

```console
mkdocs build
```

### Start a documentation mini-webserver, that automatically updates

```console
mkdocs serve
```

### Run tests in multiple python environments

```console
tox
```

***

## From within vscode

You can verify the tests using the testing flask icon on the left.

1. Brings up the testing dialog.
2. Can run or debug individual tests, by selecting them and using the icons.
3. Can rediscover, run all tests or debug all tests.

![vscode testing example](images/vscode_testing.png "VSCode Testing Example")

## On github

A small icon will have been added to github by github actions. It will be a ✅ if the tests are passing, a ❌ if they are failing and a 🟤 if the tests are still running.

You can click on it to view the logs and see what tests have passed, or what tests are still running.

![github tests example](images/github_tests_passing.png "Github Tests Passing")

## Stuff you will need to edit

- [tox.ini](tox.ini): Make sure `envlist` contains the versions of Python you want to test again. This example inclujdes
- [requirements-dev.txt](requirements-dev.txt): Make sure this includes any developer only dependancies.
- [requirements.txt](requirements.txt): This should contain dependancies required to run the application or library. If you are making an application, you should pin each package to a specific version. If you are making a library, you should accept the minimum required version to allow users more choice. A library with a pinned version FORCES the user to install that version too, and is likely to clash with other libraries.
- [docs/](docs/): The entry document is index.md, but you should write the docs as you see fit.
- [src/](src/): Update this with your package name.
- [tests/](tests/): This is where to write your tests. Files must start `test_` to be picked up by tests/

## Docstrings

See [arithmetic.py](src/python_vscode_template2/arithmetic.py) for example docstrings. These are in [Google Docstring Format](https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html).

## Dist

`flit build` will put two files in the `dist/` directory. A source file and a wheel. Both of these are directly usable by pip to install.

## Publishing docs to Github pages

You can do this with `mkdocs gh-pages`. This will push the documentation in `site/` to a github page.
You will get the URL to it from the command.

## Uploading to pypi

If you have never done this before, you need to make an account at [Pypi](https://pypi.org/).
Then in [Pypi - Manage Accounts](https://pypi.org/manage/account/), add 2FA and an API token.

Then repeat this for [TestPypi](https://test.pypi.org/) and [TestPypi - Manage Accounts](https://test.pypi.org/manage/account), add 2FA and a API token.

Then edit `.pypirc` in your home directory, and make it similar to [.pypirc-template](.pypirc-template) in this repo, except with the appropriate tokens.

To upload to pypi, make sure your git repo and working directory are up to date, and run `flit publish --repository prodpypi` or `flit pubish --repository testprod` as required. Running without `--repository` will specifically not work. This is done to make you select where to upload to.

If you publish to test and want to use it, from another virtual environment, do `pip install --index-url https://test.pypi.org/simple/ python_vscode_template`, or of course just `pip install python_vscode_template`.

The name of the package is decided by what is in [pyproject.toml](pyproject.toml), in the `[project]`, `name=` key.

## My Global VSCode Settings

- Press `CTRL K` then `CTRL T`, and select `Dark+` as the theme (or your prefered theme).
- Press `CTRL ,` then make sure `Auto Save` is set to `After Delay`.
- In the File menu, make sure `Auto Save` is ticked.

## Old Version.

You can find the old version, based on flake8 and black rather than ruff at [Python-VSCode-Template](https://github.com/davidgroves/Python-VSCode-Template).
