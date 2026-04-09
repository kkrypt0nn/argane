package main

func main() {
	err := genCommandsDocs()
	if err != nil {
		panic(err)
	}

	err = generatePolicyDocs()
	if err != nil {
		panic(err)
	}
}
