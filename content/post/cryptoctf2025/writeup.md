---
title: Crypto CTF 2025
description: writeup
date: 2025-07-15
categories:
    - writeup
tags:
    - [mpc, rsa]
math: true
---

## Introduction

どうも，Nagiです．

2025/07/12,13に行われたCryptoCTF 2025にsayonaraで参加して79位でした．

開始早々，easy問題を２つテンポよく解けたのですが，medium以上になると歯が立ちませんでした．

夜になるとチームメンバーが合流し，easy問題を１つとmedium問題を１つ解いてくれました．

今回は当日僕が解けた問題のwriteupを投稿します．

（upsolveしたら別でwriteupを投稿したいけど，時間があるかどうか...）


## Vinad

### source code

以下とは別に$(R,n,c)$が書かれたoutput.txtも配布されたがここでの記載は省略する．

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from flag import flag

def parinad(n):
	return bin(n)[2:].count('1') % 2

def vinad(x, R):
	return int(''.join(str(parinad(x ^ r)) for r in R), 2)

def genkey(nbit):
	while True:
		R = [getRandomNBitInteger(nbit) for _ in range(nbit)]
		r = getRandomNBitInteger(nbit)
		p, q = vinad(r, R), getPrime(nbit)
		if isPrime(p):
			e = vinad(r + 0x10001, R)
			if GCD(e, (p - 1) * (q - 1)) == 1:
				return (e, R, p * q), (p, q)

def encrypt(message, pubkey):
	e, R, n = pubkey
	return pow(message + sum(R), e, n)

nbit = 512
pubkey, _ = genkey(nbit)
m = bytes_to_long(flag)
assert m < pubkey[2]
c = encrypt(m, pubkey)

print(f'R = {pubkey[1]}')
print(f'n = {pubkey[2]}')
print(f'c = {c}')
```

### description

parinad関数について以下が成り立つことがわかります．

$$
\begin{align*}
\text{parinad}(a\oplus b) &= \sum\limits_{i}(a_{i}+b_{i})\mod 2 \\
&= \sum\limits_{i}a_{i} + \sum\limits_{j} b_{j}\mod 2\\
&= \text{parinad}(a)\oplus \text{parinad}(b)
\end{align*}
$$

したがって，$p$を生成したときのvinad関数の処理は次のように書けます．

$$
\begin{align*}
p &= \text{vinad}(r,R) \\
&= \text{parinad}(r\oplus R[0])\ || \cdots\ || \text{parinad}(r\oplus R[n])\\
&= \text{parinad}(r)\oplus \text{parinad}(R[0])\ ||\ \cdots\ ||\ \text{parinad}(r)\oplus \text{parinad}(R[n])
\end{align*}
$$

ここで$r$は固定の値なので$\text{parinad}(r)$は$0$か$1$のどちらかで固定です．

よって，$p = 0\oplus \text{parinad}(R[0])\ ||\ \cdots\ ||\ 0\oplus \text{parinad}(R[n])$あるいは$p = 1\oplus \text{parinad}(R[0])\ ||\ \cdots\ ||\ 1\oplus \text{parinad}(R[n])$のどちらかであることがわかります．

与えられた$R$から上記の２通りを計算し，$n$の約数である方を選ぶことで$p$が求まります．

$e$も同様にして２通りに絞れます．

正しい$e$は$\gcd(e,(p-1)(q-1))=1$を満たします．

これで秘密鍵が求まるので復号すればflagが求まります．


### solver

```python

from Crypto.Util.number import long_to_bytes

R = ...
n = ...
c = ...

def Euclid(a,b):
    r = a%b
    while r != 0:
        a,b = b,r
        r = a%b
    return b

def parinad(num):
    return bin(num)[2:].count('1') % 2

def solve():

    nbit = 512

    R_pari = ''.join(str(parinad(r_i)) for r_i in R)
    p1 = int(R_pari, 2)
    
    if n % p1 == 0:
        p = p1
    else:
        mask = pow(2, nbit) - 1
        p2 = p1 ^ mask
        if n % p2 == 0:
            p = p2
        else:
            print("どっかだめー")
            return
            
    q = n // p
    phi = (p-1)*(q-1)
    e = p
    if Euclid(e, phi) == 1:
        d = pow(e,-1,phi)
        flag = long_to_bytes((pow(c,d,n) - sum(R))%n)
        print(flag)
    else:
        e = p ^ mask
        d = pow(e,-1,phi)
        flag = long_to_bytes((pow(c,d,n) - sum(R))%n)
        print(flag)


if __name__ == '__main__':
    solve()

```



## interpol

### source code


```python

#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def randpos(n):
	if randint(0, 1):
		return True, [(-(1 + (19*n - 14) % len(flag)), ord(flag[(63 * n - 40) % len(flag)]))]
	else:
		return False, [(randint(0, 313), (-1) ** randint(0, 1) * Rational(str(getPrime(32)) + '/' + str(getPrime(32))))]

c, n, DATA = 0, 0, []
while True:
	_b, _d = randpos(n)
	H = [d[0] for d in DATA]
	if _b:
		n += 1
		DATA += _d
	else:
		if _d[0][0] in H: continue
		else:
			DATA += _d
			c += 1
	if n >= len(flag): break

A = [DATA[_][0] for _ in range(len(DATA))]
poly = QQ['x'].lagrange_polynomial(DATA).dumps()
f = open('output.raw', 'wb')
f.write(poly)
f.close()

```


### description

polyはLagrange interpolationにより得られた多項式です．

では，どのような点をLagrange interpolationに使ったかというと

- $(x,y) = ((-(1 + (19*n - 14) \% \text{len(flag)}), \text{ord}(\text{flag}[(63 * n - 40) \% \text{len(flag)}])))$
- $(x,y) = (\text{randint}(0, 313), (-1) ** \text{randint}(0, 1) * \text{Rational(str(getPrime}(32)) + '/' + \text{str(getPrime}(32))))$

という２点です．

ごちゃついていますが一言で言うと，前者はflagの情報が入った点で，後者はflagの情報がないダミーの点です．

ただし，flagの情報が入ったすべての点はLagrange interpolationに使われています．

flagの情報が入った点を見つける戦略は，polyに$x=0,1,\ldots$と代入していき，$y$の値が整数かつASCIIに対応している範囲のときはflagの点としました．

また，flagの文字が見つかる順番はぐちゃぐちゃなので，flagの何文字目が見つかったかを記録しておくことで最後に正しい順に並び替えることができます．

（余談ですが，たまたま2,3日前にShamir's secret sharingの勉強をしていてLagrange interpolationへの解像度が高かったです．ラッキー！）


### solver

```python

def solve():
    with open('output.raw', 'rb') as f:
        poly_data = f.read()

    P = loads(poly_data)

    for length in range(10, 100):
        
        flag_chars = []
        idx_list = []

        for n in range(length):
            x = -(1 + (19 * n - 14) % length)
            y = P(x)
            
            if y.is_integer() and 32 <= y <= 126:
                char = chr(int(y))
                idx = (63 * n - 40) % length
                idx_list.append(idx)
                flag_chars.append(char)
            else:
                break

        flag_list = [''] * length
        for i in range(length):
            char = flag_chars[i]
            destination_idx = idx_list[i]
            flag_list[destination_idx] = char

        flag = "".join(flag_list)

        if flag.startswith("CCTF{"):
            print(flag)
            break

if __name__ == '__main__':
    solve()

```
