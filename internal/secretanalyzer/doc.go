// Package secretanalyzer identifies possible credential exposure in already
// discovered, in-scope textual resources. It NEVER validates credentials with
// a provider, attempts authentication, or exports matched credential values.
//
// Extension guide: add a named detection rule in signatures.go, then add
// synthetic-positive and false-positive tests in detector_test.go. Keep all
// raw matches local to Detect: only Finding metadata may cross package bounds.
package secretanalyzer
