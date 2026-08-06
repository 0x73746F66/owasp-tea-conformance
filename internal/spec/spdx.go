package spec

import (
	"encoding/json"
	"fmt"
	"strings"
)

// LicenseList is the SPDX licence list, as published by the SPDX project.
//
// It is fetched rather than embedded for the same reason the API
// specifications are: the list gains identifiers and deprecates others, and a
// suite that judged a provider against a copy frozen at build time would
// eventually report a correct licence as invalid.
type LicenseList struct {
	Version string
	// IDs maps a canonical identifier to whether SPDX has deprecated it.
	IDs map[string]bool
	// Canonical maps a lowercased identifier back to its canonical spelling,
	// so a case error can be reported as a case error rather than as an
	// unknown licence.
	Canonical map[string]string
	// Exceptions are the licence-exception identifiers usable after WITH.
	Exceptions map[string]bool
}

type spdxDocument struct {
	LicenseListVersion string `json:"licenseListVersion"`
	Licenses           []struct {
		LicenseID     string `json:"licenseId"`
		IsDeprecated  bool   `json:"isDeprecatedLicenseId"`
		IsOSIApproved bool   `json:"isOsiApproved"`
	} `json:"licenses"`
	Exceptions []struct {
		LicenseExceptionID string `json:"licenseExceptionId"`
		IsDeprecated       bool   `json:"isDeprecatedLicenseId"`
	} `json:"exceptions"`
}

// LoadLicenseList parses the SPDX licence list document.
func LoadLicenseList(raw []byte) (*LicenseList, error) {
	var doc spdxDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse the SPDX licence list: %w", err)
	}
	if len(doc.Licenses) == 0 {
		return nil, fmt.Errorf("the SPDX licence list contains no licences")
	}
	list := &LicenseList{
		Version:    doc.LicenseListVersion,
		IDs:        make(map[string]bool, len(doc.Licenses)),
		Canonical:  make(map[string]string, len(doc.Licenses)),
		Exceptions: map[string]bool{},
	}
	for _, l := range doc.Licenses {
		list.IDs[l.LicenseID] = l.IsDeprecated
		list.Canonical[strings.ToLower(l.LicenseID)] = l.LicenseID
	}
	for _, e := range doc.Exceptions {
		list.Exceptions[e.LicenseExceptionID] = e.IsDeprecated
	}
	return list, nil
}

// Verdict is what the licence checker concluded about one identifier.
type Verdict int

const (
	// LicenseValid is a current SPDX identifier.
	LicenseValid Verdict = iota
	// LicenseDeprecated is a real identifier SPDX no longer recommends.
	LicenseDeprecated
	// LicenseWrongCase is a real identifier spelled with the wrong casing.
	// SPDX identifiers are case-sensitive and a consumer matching them exactly
	// will not find it.
	LicenseWrongCase
	// LicenseUnknown is not an SPDX identifier at all.
	LicenseUnknown
)

// Check classifies a single identifier. `LicenseRef-` names are a legitimate
// escape hatch in the SPDX grammar for a licence with no identifier, so they
// are accepted rather than reported as unknown.
func (l *LicenseList) Check(id string) (Verdict, string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return LicenseUnknown, ""
	}
	trimmed := strings.TrimSuffix(id, "+") // the "or later" operator
	if strings.HasPrefix(trimmed, "LicenseRef-") || strings.HasPrefix(trimmed, "DocumentRef-") {
		return LicenseValid, trimmed
	}
	if deprecated, ok := l.IDs[trimmed]; ok {
		if deprecated {
			return LicenseDeprecated, trimmed
		}
		return LicenseValid, trimmed
	}
	if canonical, ok := l.Canonical[strings.ToLower(trimmed)]; ok {
		return LicenseWrongCase, canonical
	}
	return LicenseUnknown, trimmed
}

// ExpressionProblem is one thing wrong with a licence expression.
type ExpressionProblem struct {
	Token   string
	Verdict Verdict
	Hint    string
}

// CheckExpression validates an SPDX licence expression: the identifiers joined
// by AND, OR and WITH, with parentheses.
//
// It is deliberately a token check rather than a full grammar parse. The
// question this suite asks is "would a consumer resolve every identifier in
// here", and an expression whose operators are misplaced but whose identifiers
// are all real is a different, lesser problem than one naming a licence that
// does not exist.
func (l *LicenseList) CheckExpression(expr string) []ExpressionProblem {
	var problems []ExpressionProblem
	for _, token := range tokenizeExpression(expr) {
		switch strings.ToUpper(token) {
		case "AND", "OR", "WITH", "":
			continue
		}
		verdict, canonical := l.Check(token)
		switch verdict {
		case LicenseValid:
			continue
		case LicenseDeprecated:
			problems = append(problems, ExpressionProblem{Token: token, Verdict: verdict,
				Hint: "SPDX has deprecated this identifier"})
		case LicenseWrongCase:
			problems = append(problems, ExpressionProblem{Token: token, Verdict: verdict,
				Hint: "SPDX identifiers are case-sensitive; the canonical spelling is " + canonical})
		default:
			// A WITH operand is an exception rather than a licence, so check
			// that table before calling it unknown.
			if _, ok := l.Exceptions[token]; ok {
				continue
			}
			problems = append(problems, ExpressionProblem{Token: token, Verdict: verdict,
				Hint: "not an SPDX licence identifier"})
		}
	}
	return problems
}

func tokenizeExpression(expr string) []string {
	replacer := strings.NewReplacer("(", " ", ")", " ")
	fields := strings.Fields(replacer.Replace(expr))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}
