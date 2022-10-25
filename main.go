package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/Northern-Lights/yara-parser/data"
	"github.com/Northern-Lights/yara-parser/grammar"
)

func main() {
	J2Y()
	// Y2J()
}

func Y2J() {
	const rule = `rule ExampleRule
	{
		strings:
			$my_text_string = "text here"

		condition:
			$my_text_string
	}`
	ruleset, err := grammar.Parse(strings.NewReader(rule), os.Stdout)
	if err != nil {
		log.Panicf(`Couldn't parse YARA ruleset: %s`, err)
		os.Exit(3)
	}

	enc := json.NewEncoder(os.Stdout)
	err = enc.Encode(&ruleset)
	if err != nil {
		log.Panicf(`Error writing JSON: %s`, err)
		os.Exit(6)
	}
}

func J2Y() {
	const rule = `{"file":"","imports":null,"includes":null,"rules":[{"modifiers":{"global":false,"private":false},"identifier":"ExampleRule","tags":[],"meta":null,"strings":[{"id":"$my_text_string","type":0,"text":"text here","modifiers":{"nocase":false,"ascii":false,"wide":false,"fullword":false,"private":false,"xor":null,"i":false,"s":false}}],"condition":"$my_text_string"}]}`

	var ruleset data.RuleSet
	err := json.NewDecoder(strings.NewReader(rule)).Decode(&ruleset)
	if err != nil {
		log.Printf(`Couldn't JSON decode file: %s`, err)
		os.Exit(3)
	}
	out, _ := ruleset.Serialize()
	log.Printf("%s", out)
}
