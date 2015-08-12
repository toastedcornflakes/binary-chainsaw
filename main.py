#!/usr/bin/env python3

"""
    Main:
        Loading:
        * Set executable from CLI
        * Launch all the loaders accept_file
        * Present a list of matching loaders and let the user choose

        Usage:
        * Disass with capstone from entry point
        * Follow jumps & call for recursive descent (check for library functions before trying?)
        * Eval() scripts to modify/comment/... the binary

        GUI:
        * Use PyQT/Pyside to make a basic GUI?
"""

import sys
from importlib import import_module
from glob import glob

from analyzer.analyzer import Analyzer
from capstone import *

import API


def loader_name(l):
    return l.__name__.split(".")[-1]


def load_modules():
    """ Dynamically loads file loaders modules from loader/ directory"""
    loaders = []
    loaders_files = glob("loaders/*.py")
    for loader_file in loaders_files:
        loader = import_module(loader_file.replace("/", ".")[:-3])
        if hasattr(loader, "accept_file") and hasattr(loader, "load_file"):
            loaders.append(loader)
    return loaders


def prompt_user_for_loader(valid_loaders):
    choice = 0
    while choice <= 0 or choice > len(valid_loaders):
        print("Choose a loader:")
        for i, l in enumerate(valid_loaders, 1):
            print("#", i, loader_name(l))
        try:
            choice = int(input("Choose loader number: "))
        except ValueError:
            print("Invalid number")
    return valid_loaders[choice - 1]


def ansi_bold(s):
    return "\033[1m" + s + "\033[22m"


def main(argv):
    print("#" * 64)
    print("##" + " " * 23 + "KICKASS DISASS" + " " * 23 + "##")
    print("##" + " " * 60 + "##")
    print(
        "##" +
        "Powered by Capstone {:d}.{:d} ##".format(
            CS_API_MAJOR,
            CS_API_MINOR).rjust(62))
    print("#" * 64 + "\n")

    if len(argv) <= 1:
        raise Exception("Usage: python3 main.py binary")

    loaders = load_modules()

    # open file and check for loaders that are able to disass the file
    with open(argv[1], 'rb') as f:
        valid_loaders = [l for l in loaders if l.accept_file(f)]

        if not valid_loaders:
            print("+ No loaders recognize the file")
            sys.exit(-1)

        if len(valid_loaders) >= 2:
            loader = prompt_user_for_loader(valid_loaders)
        else:
            loader = valid_loaders[0]

        # launch the actual analysis
        anal = Analyzer(loader, f)


if __name__ == '__main__':
    main(sys.argv)
