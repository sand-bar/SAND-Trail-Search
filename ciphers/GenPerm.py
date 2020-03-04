#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Created on Mar 1, 2019
@author: Shawn
'''


def GenNibblePerms(HalfBlockSize, nibble_perms=[7,4,1,6,3,0,5,2]):
    perms = [0 for i in range(HalfBlockSize)]
    assert len(nibble_perms) == HalfBlockSize // 4
    for i in range(HalfBlockSize):
        nibble_index = i // 4
        nibble_possition = i % 4
        perms[i] = 4 * nibble_perms[nibble_index] + nibble_possition

    return perms


if __name__ == '__main__':
    a = [7, 4, 1, 6, 3, 0, 5, 2]
    print(a)
    print(GenNibblePerms(32, nibble_perms=a))
