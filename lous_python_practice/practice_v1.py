#!/bin/python3

a = int(input("What is the number? "))


def xyz(a):
    if a == 33:
        return "no"

    elif a > 30 and a < 40:
        return "yes"

    else:
        return "no"

        """
        This returns yes if the number is greater than 30 and less
        than 40, but not equal to 33
        """


print(xyz(a))
