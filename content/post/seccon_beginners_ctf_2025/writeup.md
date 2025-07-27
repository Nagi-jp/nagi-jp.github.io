---
title: SECCON Beginners CTF 2025
description: writeup
date: 2025-07-27
categories:
    - writeup
tags:
    - [rsa, ecc]
math: true
---

## Introduction

どうも，Nagiです．

2025/07/26,27に開催されたSECCON Beginners CTF 2025にsayonaraで参加して2位でした！

チーム初の全完ということも相まってとても嬉しかったです．

１位のTPCさんとは全完のタイムが80秒差だったので，ちょっぴり悔しいですね〜（おめでとうございます！）

僕の呼びかけに応じて予定を空けて参加してくれたメンバーのみんなに感謝です，ありがとう！

僕個人としては，Cryptoを３問解きました．
- seesaw (10th blood)
- elliptic4b (2nd blood)
- mathmyth (チームメンバーが先に解いてた)

この３問についてwriteupを書いていきます．

## seesaw

### source

```python

import os
from Crypto.Util.number import getPrime

FLAG = os.getenv("FLAG", "ctf4b{dummy_flag}").encode()
m = int.from_bytes(FLAG, 'big')

p = getPrime(512)   
q = getPrime(16)
n = p * q
e = 65537
c = pow(m, e, n)

print(f"{n = }")
print(f"{c = }")

```


### Description

$q$が16bitなので$n$を素因数分解できてしまいます．

### solver

```python

from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
n = 362433315617467211669633373003829486226172411166482563442958886158019905839570405964630640284863309204026062750823707471292828663974783556794504696138513859209
q = 33091
p = n//q
e = 65537
phi = (p-1)*(q-1)
d = pow(e,-1,phi)
c=104442881094680864129296583260490252400922571545171796349604339308085282733910615781378379107333719109188819881987696111496081779901973854697078360545565962079


def dec(ct,d,n):
    pt = pow(ct,d,n)
    return long_to_bytes(pt)

print(dec(c,d,n))
```


## elliptic4b

### source

```python

import os
import secrets
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

flag = os.environ.get("FLAG", "CTF{dummy_flag}")
y = secrets.randbelow(secp256k1.p)
print(f"{y = }")
x = int(input("x = "))
if not secp256k1.is_point_on_curve((x, y)):
    print("// Not on curve!")
    exit(1)
a = int(input("a = "))
P = Point(x, y, secp256k1)
Q = a * P
if a < 0:
    print("// a must be non-negative!")
    exit(1)
if P.x != Q.x:
    print("// x-coordinates do not match!")
    exit(1)
if P.y == Q.y:
    print("// P and Q are the same point!")
    exit(1)
print("flag =", flag)

```

### Description

以下の２つに答えるとflagがもらえます．
1. 楕円曲線上のある点の$y$座標が与えられるので対応する$x$座標．
2. $P=(x,y)$に対して，$-P=aP$となる$a\in \mathbb{Z}_{\geq 0}$．

#### find x

楕円曲線$E(\mathbb{F_p}):y^{2}=x^{3}+7$において，ある$P\in E(\mathbb{F_p})$の$y$座標（$y_{P}$とする）が与えられるので，対応する$x$座標（$x_{P}$とする）を答えれば第一関門突破です．

$$
\begin{align*}
y_{P}^{2}&=x_{P}^{3}+7\mod p\\
\implies x_{P}^{3}&= y_{P}^{2}-7\mod p
\end{align*}
$$

となるので，$y_{P}^{2}-7$の法$p$上での3乗根を求めれば$x_{P}$を得られます．

#### answer a

次に$a\in\mathbb{Z}_{\geq 0}$として$Q=aP$を考えます．

$Q=(x_{Q},y_{Q})$が以下を満たすような$a$を求められればflagを得られます．

- $x_{P}=x_{Q}$
- $y_{P}\neq y_{Q}$

すなわち，$Q=-P$となるような$a$を見つければよいです．
残念ながら，$a\geq 0$であるから$a=-1$とはできません．

そこで，$P$の位数$n$から１を引いた値を$a$にすれば$-P=aP$を満たします．

### solver

```python

import os
os.environ['TERM'] = 'xterm'
from pwn import *


def solve():
    io = remote("elliptic4b.challenges.beginners.seccon.jp" , 9999)
    io.recvuntil(b'y = ')
    y_str = io.recvline().strip().decode()
    y = Integer(y_str) 
    print('y=',y)
    
    # https://neuromancer.sk/std/secg/secp256k1
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    K = GF(p)
    a = K(0x0000000000000000000000000000000000000000000000000000000000000000)
    b = K(0x0000000000000000000000000000000000000000000000000000000000000007)
    E = EllipticCurve(K, (a, b))
    
    x = Integer(K(y^2 - 7).nth_root(3))
    io.sendlineafter(b'x = ', str(x).encode())

    P = E(x,y)
    P_ord = P.order()
    a = P_ord - 1
    io.sendlineafter(b'a = ', str(a).encode())
    print(io.recvline())
    
if __name__ == "__main__":
    solve()
```


## mathmyth

### source

```python

from Crypto.Util.number import getPrime, isPrime, bytes_to_long
import os, hashlib, secrets


def next_prime(n: int) -> int:
    n += 1
    while not isPrime(n):
        n += 1
    return n


def g(q: int, salt: int) -> int:
    q_bytes = q.to_bytes((q.bit_length() + 7) // 8, "big")
    salt_bytes = salt.to_bytes(16, "big")
    h = hashlib.sha512(q_bytes + salt_bytes).digest()
    return int.from_bytes(h, "big")


BITS_q = 280
salt = secrets.randbits(128)

r = 1
for _ in range(4):
    r *= getPrime(56)

for attempt in range(1000):
    q = getPrime(BITS_q)
    cand = q * q * next_prime(r) + g(q, salt) * r
    if isPrime(cand):
        p = cand
        break
else:
    raise RuntimeError("Failed to find suitable prime p")

n = p * q
e = 0x10001
d = pow(e, -1, (p - 1) * (q - 1))

flag = os.getenv("FLAG", "ctf4b{dummy_flag}").encode()
c = pow(bytes_to_long(flag), e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print(f"r = {r}")

```

### Description

私の力不足で長々とした説明になっています，ご注意ください．

全体の流れとしては$q$の近似を考え，そこから$q$までの差をbrute forceといった感じです．

以下では$r' := nextprime(r), g := g(q,salt)$としています．

#### find q%r

$$
\begin{align*}
n &= q^{3}\cdot r' + q\cdot g\cdot r \mod r\\
&= q^{3}\cdot r'\mod r\\
\implies q^{3} &= n\cdot(r')^{-1} \mod r
\end{align*}
$$
3乗根を取ることで$q$%$r$の候補が求まります．

$q$を$r$で割った余りを使うと除法の定理より
$$
q = (q//r)r + (q\%r) 
$$
と書けます．

#### approximate q

$q^{3}\cdot r'$は1064bit，$q\cdot g\cdot r$は1016bitであるから$n \approx q^{3}\cdot r$'とみることができます．
$q$の近似値$\tilde{q}$を以下のように定義します．

$$
\tilde{q}\approx \sqrt[3]{\frac{n}{r'}}
$$

ここで$q$%$r$を使うことで，$\tilde{q}$よりも良い$q$の近似$q'$を以下のように定義できます．
$$
q' := (\tilde{q}//r)r + (q\%r)
$$

$q'$と$q$との差を考えます．

$$
\begin{align*}
q' - q &= (q//r)r + (q\%r) - \{(\tilde{q}//r)r + (q\%r)\}\\
&= r( q//r - \tilde{q}//r )
\end{align*}
$$

つまり，$q,q'$は$r$の定数倍の差があることがわかります．
定数倍の部分がbrute forceできるくらいの値であれば嬉しいです．


#### analysis

$q//r - q'//r=\frac{q-q'}{r}$がどれくらいの値に収まっているのかを概算します．
$\tilde{q}^{3}-q^{3} = g\cdot q$であり，$g\cdot q$は792bitです．
このことから，$\sqrt[3]{\tilde{q}^{3}-q^{3}}$は264bitくらいになります．

一方で，
$$
(\tilde{q}-q)^{3}\leq \tilde{q}^{3}-q^{3}
$$
より，$\sqrt{\tilde{q}-q)^{3}} = q-\tilde{q}$は264bit以下です．

したがって，$\frac{q-q'}{r}$は最大でも40bitだとわかります．

#### find q

以下のような式を考え，$c$をbrute forceしていく．
$$
q'-c\cdot r = (\tilde{q}//r)r + (q\%r)-c\cdot r
$$
最終的に
- $q'-c\cdot r>0$
- $(q'-c\cdot r)\mid n$

を満たすものが$q$になります．

### solver

```python

from Crypto.Util.number import long_to_bytes

n = 23734771090248698495965066978731410043037460354821847769332817729448975545908794119067452869598412566984925781008642238995593407175153358227331408865885159489921512208891346616583672681306322601209763619655504176913841857299598426155538234534402952826976850019794857846921708954447430297363648280253578504979311210518547
e = 65537
c = 22417329318878619730651705410225614332680840585615239906507789561650353082833855142192942351615391602350331869200198929410120997195750699143505598991770858416937216272158142281144782652750654697847840376002907226725362778292640956434687927315158519324142726613719655726444468707122866655123649786935639872601647255712257
r = 4788463264666184142381766080749720573563355321283908576415551013379

np = next_prime(r)
print('next_prime(r) = ',np)
r_factors = factor(r)
primes = [p for p, e in r_factors]
print('primes=', primes)

F = Zmod(r)
a = (n * inverse_mod(np, r)) % r
temp = F(a).nth_root(3, all=True)
q_low_cand = [int(i) for i in temp]

# brute force
q_approx3 = Integer(n // np)
q_approx, is_exact = q_approx3.nth_root(3, truncate_mode=True)
print('q_approx=', q_approx)

for q_low in q_low_cand:
    q_cand = (q_approx // r) * r + q_low
    for k in range(2**10):
        q_test = q_cand - k * r
        if q_test > 0 and n % q_test == 0:
            print('k=', k)
            print('q=', q_test)
            p = n // q_test
            phi = (p - 1) * (q_test - 1)
            d = inverse_mod(e, phi)
            m = power_mod(c, d, n)
            flag = long_to_bytes(m)
            print('flag = ', flag.decode())
            break

```