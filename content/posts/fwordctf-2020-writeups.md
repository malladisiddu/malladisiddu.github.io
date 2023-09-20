---
title: FwordCTF 2020
date: 2020-08-30
author: Siddartha Malladi
categories:
  - Crypto
tags:
  - LCG
  - PRNG
---
![logo](https://ctftime.org/media/events/logo-twitter.png)  

I thoroughly enjoyed playing FwordCTF-2020, but I could manage to play only for 7 hours.  
## Randomness 
> [Randomness.py](https://github.com/malladisiddu/Crypto-writeups/blob/master/FwordCTF/Randomness/Randomness.py) 

Given an encryption file in which the output is commented, 
```python
from Crypto.Util.number import *
from random import *

flag="TODO"
p=getPrime(64)
a=getrandbits(64)
b=getrandbits(64)
X=[]
X.append((a*getrandbits(64)+b)%p)
c=0
while c<len(flag):
	X.append((a*X[c]+b)%p)
	c+=1

output=[]

for i in range(len(flag)):
	output.append(ord(flag[i])^X[i])

print (output)

#output:[6680465291011788243L, 5100570103593250421L, 5906808313299165060L, 1965917782737693358L, 9056785591048864624L, 1829758495155458576L, 6790868899161600055L, 1596515234863242823L, 1542626304251881891L, 8104506805098882719L, 1007224930233032567L, 3734079115803760073L, 7849173324645439452L, 8732100672289854567L, 5175836768003400781L, 1424151033239111460L, 1199105222454059911L, 1664215650827157105L, 9008386209424299800L, 484211781780518254L, 2512932525834758909L, 270126439443651096L, 3183206577049996011L, 3279047721488346724L, 3454276445316959481L, 2818682432513461896L, 1198230090827197024L, 6998819122186572678L, 9203565046169681246L, 2238598386754583423L, 467098371562174956L, 5653529053698720276L, 2015452976526330232L, 2551998512666399199L, 7069788985925185031L, 5960242873564733830L, 8674335448210427234L, 8831855692621741517L, 6943582577462564728L, 2159276184039111694L, 8688468346396385461L, 440650407436900405L, 6995840816131325250L, 4637034747767556143L, 3074066864500201630L, 3089580429060692934L, 2636919931902761401L, 5048459994558771200L, 6575450200614822046L, 666932631675155892L, 3355067815387388102L, 3494943856508019168L, 3208598838604422062L, 1651654978658074504L, 1031697828323732832L, 3522460087077276636L, 6871524519121580258L, 6523448658792083486L, 127306226106122213L, 147467006327822722L, 3241736541061054362L, 8781435214433157730L, 7267936298215752831L, 3411059229428517472L, 6597995245035183751L, 1256684894889830824L, 6272257692365676430L, 303437276610446361L, 8730871523914292433L, 6472487383860532571L, 5022165523149187811L, 4462701447753878703L, 1590013093628585660L, 4874224067795612706L]
``` 
The idea to solve the challenge is very simple, if we can find `X` and XOR it with the given `output` we get the flag. 

After going through the code, I got to know that it involves randombits, the topic which I've never solved any challenge based on it. But I know that it is related to [Pseudo Random Number Generator](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)(PRNG). Anyways, lets break the code into parts and understand it. 
First lets understand the final part of the code,  
```python
output=[]
for i in range(len(flag)):
	output.append(ord(flag[i])^X[i])
print (output)
``` 
We understood that, `flag` and an array `X` were XORed and appended to `output` array. Here, we only know `output`, `X` & `flag` are yet to be found. 
Guess what? 
Since we know the flag format we can find some values of `X`,  
```python
flag = "FwordCTF{"
output = [6680465291011788243, 5100570103593250421, 5906808313299165060, 1965917782737693358, 9056785591048864624, 1829758495155458576, 6790868899161600055, 1596515234863242823, 1542626304251881891, 8104506805098882719, 1007224930233032567, 3734079115803760073, 7849173324645439452, 8732100672289854567, 5175836768003400781, 1424151033239111460, 1199105222454059911, 1664215650827157105, 9008386209424299800, 484211781780518254, 2512932525834758909, 270126439443651096, 3183206577049996011, 3279047721488346724, 3454276445316959481, 2818682432513461896, 1198230090827197024, 6998819122186572678, 9203565046169681246, 2238598386754583423, 467098371562174956, 5653529053698720276, 2015452976526330232, 2551998512666399199, 7069788985925185031, 5960242873564733830, 8674335448210427234, 8831855692621741517, 6943582577462564728, 2159276184039111694, 8688468346396385461, 440650407436900405, 6995840816131325250, 4637034747767556143, 3074066864500201630, 3089580429060692934, 2636919931902761401, 5048459994558771200, 6575450200614822046, 666932631675155892, 3355067815387388102, 3494943856508019168, 3208598838604422062, 1651654978658074504, 1031697828323732832, 3522460087077276636, 6871524519121580258, 6523448658792083486, 127306226106122213, 147467006327822722, 3241736541061054362, 8781435214433157730, 7267936298215752831, 3411059229428517472, 6597995245035183751, 1256684894889830824, 6272257692365676430, 303437276610446361, 8730871523914292433, 6472487383860532571,5022165523149187811, 4462701447753878703, 1590013093628585660, 4874224067795612706]  
X = []
for i in range(len(flag)):
    X.append(ord(flag[i])^output[i])
``` 
Here is the output, 
```
In [2]: X
Out[2]: 
[6680465291011788181,
 5100570103593250306,
 5906808313299165163,
 1965917782737693404,
 9056785591048864532,
 1829758495155458643,
 6790868899161600099,
 1596515234863242753,
 1542626304251881944]
``` 
Now lets find the remaining values of `X` by analysing the code involved in forming it, 
```python
p=getPrime(64)
a=getrandbits(64)
b=getrandbits(64)
X=[]
X.append((a*getrandbits(64)+b)%p)
c=0
while c<len(flag):
	X.append((a*X[c]+b)%p)
	c+=1
``` 
We understood that `p` is a random **prime number**, `a` & `b` are any two random numbers. Also we can understand that, this `a*getrandbits(64)+b)%p` is the part which is producing `X[i]`. But at first it seeded an initial value into `X`. Now, for any noob like me two questions will arise,

**[1] What is the type of PRNG used?**

**[2] How to crack it?** 

So, I have googled for list of PRNG's. I got the list [here](https://en.wikipedia.org/wiki/List_of_random_number_generators). My idea is to  google each Random Number Generator(RNG) and finding similarity to our code. Fortunately, I found it. It is [Linear Congruential Generator](https://en.wikipedia.org/wiki/Linear_congruential_generator)(LCG). 

This equation confirmed me that it is an LCG,

$$ \(X_{n+1}\) = \(aX_{n}+c\)\pmod m $$

### Cracking LCG
I have referred to many articles to find the answer for the 2nd question, and I got to know that LCG is the easiest of all PRNG's for both implementing & cracking. Let's crack it, 
Let us understand the terminology here,  
`p` - modulus  
`a` - multiplier  
`b` - increment  
Unfortunately, We don't the values of all the three. Let us understand this `a*getrandbits(64)+b)%p` working, 
```
s1 = s0*a + b  (mod p)
s2 = s1*a + b  (mod p)
s3 = s2*a + b  (mod p)
``` 
Its feeding back the intial seed to find the next one. Next one to find the next one & so on. Let us rearrange the equations a bit, 
```
s1 - (s0*a + b) = k_1 * p
s2 - (s1*a + b) = k_2 * p
s3 - (s2*a + b) = k_3 * p
``` 
Its unreal to solve 3 equations with 6 unknowns, but number theory made it real by using simple property i.e., if we have few random multiples of p, with large probability their gcd will be equal to p.
Let us manipulate the above equations a bit, 
```
t0 = s1 - s0
t1 = s2 - s1 = (s1*a + b) - (s0*a + b) = a*(s1 - s0) = a*t0 (mod p)
t2 = s3 - s2 = (s2*a + b) - (s1*a + b) = a*(s2 - s1) = a*t1 (mod p)
t3 = s4 - s3 = (s3*a + b) - (s2*a + b) = a*(s3 - s2) = a*t2 (mod p)
``` 
Final equation to solve this is, 
```
t2*t0 - t1*t1 = (a*a*t0 * t0) - (a*t0 * a*t0) = 0 (mod p)
``` 
Let us define python function to crack the modulus, 
```python
def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return modulus
``` 
Now we got the modulus, its pretty simple to find multiplier & increment. Let us consider the first two equations and subtract them 
```
s1 = x0*a + b  (mod p)
s_2 = x1*a + b  (mod p)

s_2 - s_1 = s1*a - s0*a  (mod p)
s_2 - s_1 = a*(s1 - s0)  (mod p)
a = (s_2 - s_1)/(s_1 - s_0)  (mod p)
``` 
that's it we got `a` and now `b` can be retrieved by by using only one equation as we know all other values in the equation. Consider the first equation, 
```
s1 = s0*a + b   (mod p)
``` 
After rearranging, 
```
b  = s1 - s0*a  (mod p)
``` 
Let us put this in a function, 
```python
def crack_lcg(seeds):
    a = ((seeds[2] - seeds[1]) * invert(seeds[1] - seeds[0], p)) % p 
    return a, (seeds[1] - seeds[0]*a) % p
``` 
### Final Exploit
Wrapping up everything from all the understanding we got from the above discussion, 
```python
from functools import reduce
from gmpy2 import gcd,gcdext,invert

def crack_lcg(seeds):
    a = ((seeds[2] - seeds[1]) * invert(seeds[1] - seeds[0], p)) % p 
    return a, (seeds[1] - seeds[0]*a) % p
def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return modulus
flag = "FwordCTF{"
output = [6680465291011788243, 5100570103593250421, 5906808313299165060, 1965917782737693358, 9056785591048864624, 1829758495155458576, 6790868899161600055, 1596515234863242823, 1542626304251881891, 8104506805098882719, 1007224930233032567, 3734079115803760073, 7849173324645439452, 8732100672289854567, 5175836768003400781, 1424151033239111460, 1199105222454059911, 1664215650827157105, 9008386209424299800, 484211781780518254, 2512932525834758909, 270126439443651096, 3183206577049996011, 3279047721488346724, 3454276445316959481, 2818682432513461896, 1198230090827197024, 6998819122186572678, 9203565046169681246, 2238598386754583423, 467098371562174956, 5653529053698720276, 2015452976526330232, 2551998512666399199, 7069788985925185031, 5960242873564733830, 8674335448210427234, 8831855692621741517, 6943582577462564728, 2159276184039111694, 8688468346396385461, 440650407436900405, 6995840816131325250, 4637034747767556143, 3074066864500201630, 3089580429060692934, 2636919931902761401, 5048459994558771200, 6575450200614822046, 666932631675155892, 3355067815387388102, 3494943856508019168, 3208598838604422062, 1651654978658074504, 1031697828323732832, 3522460087077276636, 6871524519121580258, 6523448658792083486, 127306226106122213, 147467006327822722, 3241736541061054362, 8781435214433157730, 7267936298215752831, 3411059229428517472, 6597995245035183751, 1256684894889830824, 6272257692365676430, 303437276610446361, 8730871523914292433, 6472487383860532571,5022165523149187811, 4462701447753878703, 1590013093628585660, 4874224067795612706]  
X = []
for i in range(len(flag)):
    X.append(ord(flag[i])^output[i])
p = crack_unknown_modulus(X)
a, b = crack_lcg(X)
for i in range(1,len(X)):
	assert X[i] == (X[i-1]*a + b) % p
s = []
s.append(X[0])
for i in range(1,len(output)):
	s.append((s[i-1]*a + b)%p)
flag = ""
for i in range(len(output)):
	flag+= chr(s[i]^output[i])
print("[+] Flag: ",flag)
``` 
**Flag:** `FwordCTF{LCG_easy_to_break!That_was_a_mistake_choosing_it_as_a_secure_way}` 

You can find my entire exploit [here](https://github.com/malladisiddu/Crypto-writeups/blob/master/FwordCTF/Randomness/lcgcrack.py). If you have any queries, feedback, suggestions either you can put them in comment section or you can ping me via twitter [@st0ic3r](https://twitter.com/st0ic3r).

Alright, See you next time

Bu, Bye !
