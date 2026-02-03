package errors

import (
	"errors"
	"strings"
)

type multiError []error

func (e multiError) Error() string {
	var r strings.Builder
	r.WriteString("multierr: ")
	for _, err := range e {
		r.WriteString(err.Error())
		r.WriteString(" | ")
	}
	return r.String()
}

// Unwrap returns all wrapped errors for Go 1.20+ errors.Is/As support.
func (e multiError) Unwrap() []error {
	return []error(e)
}

// Combine combines multiple errors into one.
// Returns nil if all errors are nil.
func Combine(maybeError ...error) error {
	var errs multiError
	for _, err := range maybeError {
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// AllEqual returns true if all errors in actual match expected.
func AllEqual(expected error, actual error) bool {
	switch errs := actual.(type) {
	case multiError:
		if len(errs) == 0 {
			return false
		}
		for _, err := range errs {
			if !errors.Is(err, expected) {
				return false
			}
		}
		return true
	default:
		return errors.Is(errs, expected)
	}
}
