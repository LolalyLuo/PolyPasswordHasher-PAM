#!/bin/bash
gcc -o pam_test.o test.c -lpam -lpam_misc
sudo chown root:root pam_test.o
sudo chmod +s pam_test.o
