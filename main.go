package main

import (
	"bufio"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

const privatePath = "./private.txt"
const publicPath = "./public.txt"

var (
	blockSize = 2
	bigOne    = big.NewInt(1)
)

type pubKey struct {
	n *big.Int
	e *big.Int
}

type priKey struct {
	n *big.Int
	d *big.Int
}

func choosePQ() (*big.Int, *big.Int) {
	lowerBound := big.NewInt(10)
	lowerBound.Exp(lowerBound, big.NewInt(75), nil)
	upperBound := big.NewInt(10)
	upperBound.Exp(upperBound, big.NewInt(100), nil)
	p := big.NewInt(0)
	q := big.NewInt(0)
	for true {
		rand.Seed(time.Now().UnixNano())
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		p.Rand(random, upperBound)
		if p.Cmp(lowerBound) > 0  {
			if p.ProbablyPrime(10)  {
				break
			}
		}
	}
	for true {
		rand.Seed(time.Now().UnixNano())
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		q.Rand(random, upperBound)
		if q.Cmp(lowerBound) > 0 {
			if q.ProbablyPrime(10) {
				break
			}
		}
	}
	return p, q
}

func chooseE(totient *big.Int) *big.Int {
	var res *big.Int
	tmp := big.NewInt(0)
	for true {
		r := big.NewInt(0)
		r.Rand(rand.New(rand.NewSource(time.Now().UnixNano())), totient)
		r.Add(r, big.NewInt(2))
		tmp.GCD(nil, nil, r, totient)
		if tmp.Cmp(bigOne) == 0 {
			res = r
			break
		}
	}
	return res
}

func calD(e *big.Int, totient *big.Int) *big.Int {
	d := big.NewInt(0)
	d.ModInverse(e, totient)
	return d
}

func getKey() (pubKey, priKey) {
	p, q := choosePQ()
	n := big.NewInt(0)
	n.Mul(p, q)
	p.Sub(p, big.NewInt(1))
	q.Sub(q, big.NewInt(1))
	totient := p.Mul(p, q)
	e := chooseE(totient)
	d := calD(e, totient)

	return pubKey{n, e}, priKey{n, d}
}

func (public pubKey) encrypt(message []rune) []string {
	var (
		res []string
		tmp []int
	)
	b := int(message[0])
	for i := 1; i < len(message); i++ {
		if i%blockSize == 0 {
			tmp = append(tmp, b)
			b = 0
		}
		b = b*1000 + int(message[i])
	}
	tmp = append(tmp, b)
	for i := 0; i < len(tmp); i++ {
		bigTmpI := big.NewInt(int64(tmp[i]))
		bigTmpI.Exp(bigTmpI, public.e, public.n)
		res = append(res, bigTmpI.String())
	}
	return res
}

func (private priKey) decrypt(cipher []string) []rune {
	var (
		tmp    []*big.Int
		tmpRes []string
		res []rune
	)
	for i := 0; i < len(cipher); i++ {
		bigB := big.NewInt(0)
		bigB, ok := bigB.SetString(cipher[i], 0)
		if !ok {
			log.Fatalln("string to big.Int failed")
		}
		bigB.Exp(bigB, private.d, private.n)
		tmp = append(tmp, bigB)

		var aRes string
		for j := 1; j < blockSize; j++ {
			tmpI := big.NewInt(tmp[i].Int64())
			aRes = tmpI.Mod(tmp[i], big.NewInt(1000)).String()
			tmp[i].Div(tmp[i], big.NewInt(1000))
			tmpRes = append(tmpRes, tmp[i].String())
			tmpRes = append(tmpRes, aRes)
		}
	}
	for _, v := range tmpRes {
		intV, err := strconv.Atoi(v)
		if err != nil {
			log.Fatalln(err)
		}
		res = append(res, rune(intV))
	}
	return res
}

func writeKey(public pubKey, private priKey) {
	f0, err := os.Create(publicPath)
	if err != nil {
		log.Fatalln(err)
	}
	w0 := bufio.NewWriter(f0)
	fmt.Fprint(w0, public.n)
	fmt.Fprint(w0, ",")
	fmt.Fprintln(w0, public.e)
	w0.Flush()

	f1, err := os.Create(privatePath)
	if err != nil {
		log.Fatalln(err)
	}
	w1 := bufio.NewWriter(f1)
	fmt.Fprint(w1, private.n)
	fmt.Fprint(w1, ",")
	fmt.Fprintln(w1, private.d)
	w1.Flush()
	fmt.Println("Public key and private key have been written successfully!")
}

func readKey() (pubKey, priKey) {
	var public pubKey
	var private priKey
	f0, err := os.Open(publicPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer f0.Close()

	scanner0 := bufio.NewScanner(f0)
	for scanner0.Scan() {
		tmpN := big.NewInt(0)
		tmpE := big.NewInt(0)
		value := scanner0.Text()
		res := strings.Split(value, ",")
		tmpN, ok := tmpN.SetString(res[0], 0)
		if !ok {
			log.Println("Reading public key: string N to big int failed!")
		}
		tmpE, ok = tmpE.SetString(res[1], 0)
		if !ok {
			log.Println("Reading public key: string E to big int failed!")
		}
		public.n, public.e = tmpN, tmpE
	}

	f1, err := os.Open(privatePath)
	if err != nil {
		log.Fatalln(err)
	}
	defer f1.Close()

	scanner1 := bufio.NewScanner(f1)
	for scanner1.Scan() {
		tmpN := big.NewInt(0)
		tmpD := big.NewInt(0)
		value := scanner1.Text()
		res := strings.Split(value, ",")
		tmpN, ok := tmpN.SetString(res[0], 0)
		if !ok {
			log.Println("Reading public key: string N to big int failed!")
		}
		tmpD, ok = tmpD.SetString(res[1], 0)
		if !ok {
			log.Println("Reading public key: string E to big int failed!")
		}
		private.n, private.d = tmpN, tmpD
	}
	return public, private
}

func main() {
	var public pubKey
	var private priKey
	fmt.Println("Whether generate new keys or not? (y/n)")
	var first string
	fmt.Scanf("%s", &first)
	if first == "y" {
		public, private = getKey()
		writeKey(public, private)
	} else {
		public, private = readKey()
	}

	fmt.Println("encrypt or decrypt? (e/d)")
	var second string
	fmt.Scanf("%s", &second)
	if second == "e" {
		fmt.Println("Please input message")
		var message string
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			message = scanner.Text()
		}
		cipher := public.encrypt([]rune(message))
		fmt.Print("cipher is ")
		fmt.Println(cipher)
	} else if second == "d" {
		fmt.Println("Please input cipher")
		var cipher string
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			cipher = scanner.Text()
		}
		res := strings.Split(cipher, " ")
		oriM := private.decrypt(res)
		fmt.Println("message is " + string(oriM))
	}
}
