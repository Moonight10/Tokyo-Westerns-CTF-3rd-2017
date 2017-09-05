import pwn
import os
from Crypto.Util.number import *

p = 160634950613302858781995506902938412625377360249559915379491492274326359260806831823821711441204122060415286351711411013883400510041411782176467940678464161205204391247137689678794367049197824119717278923753940984084059450704378828123780678883777306239500480793044460796256306557893061457956479624163771194201
g = 2

bits = ''
if __name__ == '__main__':
	
	r = pwn.remote('ppc2.chal.ctf.westerns.tokyo',28459) 

	r.sendline(hex(0))
	c0 = int(r.readline().strip(), 16)

	for n in range(0x200):
		r.sendline(hex(1<<n))
		cn = int(r.readline().strip(), 16)

		if (c0 * pow(g, 1<<n, p))%p == cn:
			bits = '0' + bits

		if (cn * pow(g, 1<<n, p))% p == c0:
			bits = '1' + bits

		print 'n:',n
		print 'bits',hex(int(bits, 2))

	print 'flag',long_to_bytes(int(bits,2))