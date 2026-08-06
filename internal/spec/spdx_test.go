package spec

import "testing"

const licenceList = `{
  "licenseListVersion": "3.28.0",
  "licenses": [
    {"licenseId": "Apache-2.0", "isDeprecatedLicenseId": false},
    {"licenseId": "MIT", "isDeprecatedLicenseId": false},
    {"licenseId": "GPL-2.0-only", "isDeprecatedLicenseId": false},
    {"licenseId": "GPL-2.0", "isDeprecatedLicenseId": true}
  ],
  "exceptions": [
    {"licenseExceptionId": "Classpath-exception-2.0", "isDeprecatedLicenseId": false}
  ]
}`

func list(t *testing.T) *LicenseList {
	t.Helper()
	l, err := LoadLicenseList([]byte(licenceList))
	if err != nil {
		t.Fatalf("load the licence list: %v", err)
	}
	return l
}

func TestCheckClassifiesIdentifiers(t *testing.T) {
	l := list(t)

	cases := map[string]Verdict{
		"Apache-2.0":            LicenseValid,
		"GPL-2.0-only":          LicenseValid,
		"GPL-2.0-only+":         LicenseValid, // the "or later" operator
		"LicenseRef-Acme-Inner": LicenseValid, // the grammar's escape hatch
		"GPL-2.0":               LicenseDeprecated,
		"apache-2.0":            LicenseWrongCase,
		"APACHE-2.0":            LicenseWrongCase,
		"Apache 2.0":            LicenseUnknown,
		"ASL 2.0":               LicenseUnknown,
		"":                      LicenseUnknown,
	}
	for id, want := range cases {
		if got, _ := l.Check(id); got != want {
			t.Errorf("Check(%q) is %v, expected %v", id, got, want)
		}
	}

	// A wrong-case identifier must come back with the spelling a consumer
	// needs, since that is the whole remedy.
	if _, canonical := l.Check("apache-2.0"); canonical != "Apache-2.0" {
		t.Errorf("the canonical spelling reported was %q", canonical)
	}
}

func TestCheckExpressionWalksTheOperators(t *testing.T) {
	l := list(t)

	if problems := l.CheckExpression("Apache-2.0 OR MIT"); len(problems) != 0 {
		t.Errorf("a valid expression reported %d problems: %+v", len(problems), problems)
	}
	if problems := l.CheckExpression("(MIT AND Apache-2.0) OR GPL-2.0-only"); len(problems) != 0 {
		t.Errorf("parentheses were not handled: %+v", problems)
	}
	if problems := l.CheckExpression("GPL-2.0-only WITH Classpath-exception-2.0"); len(problems) != 0 {
		t.Errorf("a WITH exception was rejected: %+v", problems)
	}

	problems := l.CheckExpression("MIT OR Apache 2.0")
	if len(problems) == 0 {
		t.Fatal("an expression naming a licence that does not exist was accepted")
	}
	// The operands are checked individually, so the report names the token that
	// is wrong and not the whole expression.
	for _, p := range problems {
		if p.Token == "MIT" {
			t.Errorf("a valid operand was reported as a problem: %+v", p)
		}
	}
}
