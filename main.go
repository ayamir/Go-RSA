package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"time"
)

const privatePath = "./private.txt"
const publicPath = "./public.txt"

var (
	blockSize = 2
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
	// lowerBound as 10^75
	lowerBound := big.NewInt(10)
	lowerBound.Exp(lowerBound, big.NewInt(75), nil)
	// upperBound as 10^100
	upperBound := big.NewInt(10)
	upperBound.Exp(upperBound, big.NewInt(100), nil)
	p := big.NewInt(0)
	q := big.NewInt(0)
	// make 10^75 < p, q < 10^100 and p, q is prime
	for true {
		rand.Seed(time.Now().UnixNano())
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		p.Rand(random, upperBound)
		if p.Cmp(lowerBound) > 0 && p.ProbablyPrime(10) {
			break
		}
	}
	for true {
		rand.Seed(time.Now().UnixNano())
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		q.Rand(random, upperBound)
		if q.Cmp(lowerBound) > 0 && q.ProbablyPrime(10) {
			break
		}
	}
	return p, q
}

func chooseE(totient *big.Int) *big.Int {
	var e *big.Int
	tmp := big.NewInt(0)
	for true {
		r := big.NewInt(0)
		random := rand.New(rand.NewSource(time.Now().UnixNano()))
		r.Rand(random, totient)
		r.Add(r, big.NewInt(2))
		tmp.GCD(nil, nil, r, totient)
		if tmp.Cmp(big.NewInt(1)) == 0 {
			e = r
			break
		}
	}
	return e
}

func calD(e *big.Int, totient *big.Int) *big.Int {
	d := big.NewInt(0)
	d.ModInverse(e, totient)
	return d
}

func getKey() (*pubKey, *priKey) {
	p, q := choosePQ()
	n := big.NewInt(0)
	n.Mul(p, q)
	p.Sub(p, big.NewInt(1))
	q.Sub(q, big.NewInt(1))
	totient := p.Mul(p, q)
	e := chooseE(totient)
	d := calD(e, totient)

	return &pubKey{n, e}, &priKey{n, d}
}

func (public *pubKey) encrypt(message []rune) []string {
	var (
		// store result as string
		res []string
		// store block content as int
		tmp []int
	)
	// two ASCII characters as a input block
	b := int(message[0])
	for i := 1; i < len(message); i++ {
		if i%blockSize == 0 {
			tmp = append(tmp, b)
			b = 0
		}
		// multiply 1000 due to ASCII is 3 bit(0~127)
		b = b*1000 + int(message[i])
	}
	tmp = append(tmp, b)
	// now b is original block content like this: 101101

	// encrypt for each block
	for i := 0; i < len(tmp); i++ {
		bigTmpI := big.NewInt(int64(tmp[i]))
		bigTmpI.Exp(bigTmpI, public.e, public.n)
		res = append(res, bigTmpI.String())
	}
	return res
}

func (private *priKey) decrypt(cipher []string) []rune {
	var (
		// store original block content as int
		tmp []int
		// store results as character
		res []rune
	)
	for i := 0; i < len(cipher); i++ {
		bigB := big.NewInt(0)
		bigB, ok := bigB.SetString(cipher[i], 0)
		if !ok {
			log.Fatalln("string to big.Int failed")
		}
		// decrypt for each block
		bigB.Exp(bigB, private.d, private.n)
		// now bigB is original block content like this: 101101
		tmp = append(tmp, int(bigB.Int64()))

		var aRes rune
		for j := 1; j < blockSize; j++ {
			aRes = rune(tmp[i] % 1000)
			tmp[i] /= 1000
			res = append(res, rune(tmp[i]))
			res = append(res, aRes)
		}
	}
	return res
}

func writeKey(public *pubKey, private *priKey) {
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

func readKey() (*pubKey, *priKey) {
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
	return &public, &private
}

func writeFile(filename string, strArr []string) error {
	var res error
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalln(err)
	}
	w := bufio.NewWriter(f)
	for _, str := range strArr {
		fmt.Fprint(w, str)
		fmt.Fprint(w, " ")
	}
	res = w.Flush()
	return res
}

func readFile(filename string) (strArr []string, res error) {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	scn := bufio.NewScanner(f)
	for scn.Scan() {
		value := scn.Text()
		value = strings.TrimSpace(value)
		strArr = strings.Split(value, " ")
		return
	}
	return nil, errors.New("read cipher from file \"" + filename + "\"failed")
}

func main() {
	var public *pubKey
	var private *priKey
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
		var third string
		fmt.Println("Do you want to write cipher to a file? (y/n)")
		if scanner.Scan() {
			third = scanner.Text()
		}
		if third == "y" {
			fmt.Println("Please input filename: ")
			var fourth string
			if scanner.Scan() {
				fourth = scanner.Text()
			}
			if err := writeFile(fourth, cipher); err == nil {
				fmt.Println("cipher has been stored successfully!")
			} else {
				fmt.Println("store failed!")
			}
		}
	} else if second == "d" {
		scanner := bufio.NewScanner(os.Stdin)
		var third string
		fmt.Println("Please choose read from file or input via stdin? (f/s)")
		if scanner.Scan() {
			third = scanner.Text()
			if third == "s" {
				fmt.Println("Please input cipher")
				var cipher string
				if scanner.Scan() {
					cipher = strings.TrimSpace(scanner.Text())
				}
				res := strings.Split(cipher, " ")
				oriM := private.decrypt(res)
				fmt.Println("message is " + string(oriM))
			} else if third == "f" {
				var fourth string
				fmt.Println("Please input filename")
				if scanner.Scan() {
					fourth = scanner.Text()
				}
				cipher, err := readFile(fourth)
				if err != nil {
					log.Fatal(err)
				} else {
					oriM := private.decrypt(cipher)
					fmt.Println("message is " + string(oriM))
				}
			}
		}
	}
}
