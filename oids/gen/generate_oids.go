package main

import (
	"flag"
	"fmt"
	"io"
	"bufio"
	"os"
	"strings"
	"regexp"
)

// Generate OID -> naming map using the nice openssl objects definitions. Formatting
// (and this parsing) is kind of wonky but ¯\_(ツ)_/¯.
// https://github.com/openssl/openssl/blob/4950f8885c8384b945a7a801f47319b9e29344e6/crypto/objects/objects.txt

func parseAliases(alias string) []string {
	oid := []string{}
	for _, a := range strings.Split(alias, "_") {
		n, ok := aliases[a]
		if !ok {
			if n, ok := aliases[alias]; ok {
				return []string{n}
			}
			panic(fmt.Sprintf("no known oid for alias %q (full: %q)", a, alias))
		}
		oid = append(oid, n)
	}
	return oid
}

var (
	numReg = regexp.MustCompile(`^\d+$`)
	wsReg = regexp.MustCompile(`^\s*$`)
)

func parseDef(def string) string {
	def = strings.TrimRight(def, " ")
	oid := []string{}
	for _, s := range strings.Split(def, " ") {
		if numReg.MatchString(s) {
			oid = append(oid, s)
		} else {
			oid = append(oid, parseAliases(s)...)
		}
	}
	return strings.Join(oid, ".")
}

var (
	aliases = map[string]string{}

	preamble = `package oids

// BLERRRGHH

`
)

func main() {
	input := flag.String("input", "objects.txt", "")
	output := flag.String("output", "objects.go", "")
	flag.Parse()

	if *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "both --input and --output are required to be non-empty")
		os.Exit(1)
	}

	f, err := os.Open(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open %q: %s\n", *input, err)
		os.Exit(1)
	}
	defer func() {err = f.Close(); if err != nil { fmt.Fprintf(os.Stderr, "failed to close file: %s\n", err); os.Exit(1) }}()

	lastOID := ""
	cname := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err = scanner.Err(); err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "failed to read line: %s\n", err)
			os.Exit(1)
		}
		line := scanner.Text()
		// Strip tabs
		// line = strings.Replace(line, "\t", "", -1) // this breaks some aliases :/
		line = strings.ToLower(line)

		if wsReg.MatchString(line) || strings.HasPrefix(line, "\t") || strings.HasPrefix(line, " "){
			continue
		}
		fmt.Println(line)

		// Ignore comments and things with no actual OIDs
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "!") {
			if !strings.HasPrefix(line, "!module") && !strings.HasPrefix(line, "!alias") && !strings.HasPrefix(line, "!cname") {
				continue
			}
			// Deal with aliases & modules
			line = strings.Replace(line, "\t", " ", -1)
			if strings.HasPrefix(line, "!module") {
				aliases[line[len("!module "):]] = lastOID
			}
			if strings.HasPrefix(line, "!alias") {
				fields := strings.Split(line, " ")
				name := fields[1]
				def := strings.Join(fields[2:], " ")
				oid := parseDef(def)
				aliases[name] = oid
				if strings.Contains(name, "_") {
					// do both
					name = strings.Replace(name, "_", "-", -1)
					aliases[name] = oid
				}
			}
			if strings.HasPrefix(line, "!cname") {
				cname = line[len("!cname "):]
			}
			continue
		}

		line = strings.Replace(line, "\t", "", -1)
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			panic(fmt.Sprintf("line doesn't contain expected number of fields (%d): %s", len(fields), line))
		}
		oid := parseDef(fields[0])
		var name string
		if cname != "" {
			name = cname
		} else {
			name = fields[1]
			if name == "" || name == " " {
				name = fields[2]
			}
		}
		name = strings.Trim(name, " ")
		aliases[name] = oid
		lastOID = oid
		cname = ""
	}

	fmt.Println("\n\nAlias map:")
	for k, v := range aliases {
		fmt.Printf("%s: %s\n", k, v)
	}

	multiOIDs := map[string][]string{}
	for k, v := range aliases {
		multiOIDs[v] = append(multiOIDs[v], k)
	}

	oids := map[string]string{}
	for k, v := range multiOIDs {
		var name string
		if len(v) > 1 {
			for _, n := range v {
				if strings.Contains(n, "_") {
					name = n
					break
				}
			}
			if name == "" {
				name = v[0]
			}
		} else {
			name = v[0]
		}
		oids[k] = name
	}

	// create/truncate file, shove preabmle in and build the map
	o, err := os.OpenFile(*output, os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.ModePerm)
	if err != nil {
		// something
	}
	defer o.Close()
	_, err = o.Write([]byte(preamble))
	if err != nil {
		// something
	}
	_, err = o.Write([]byte("var OIDs = map[string]string{\n"))
	if err != nil {
		// something
	}
	for k, v := range oids {
		_, err = o.Write([]byte(fmt.Sprintf("\t\"%s\": \"%s\",\n", k, v)))
	if err != nil {
		// something
	}
	}
	_, err = o.Write([]byte("}\n"))
	if err != nil {
		// something
	}

	// done
}
