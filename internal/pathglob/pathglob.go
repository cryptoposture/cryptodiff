package pathglob

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type Pattern struct {
	raw          string
	basenameOnly bool
	re           *regexp.Regexp
}

func CompileAll(globs []string) ([]Pattern, error) {
	out := make([]Pattern, 0, len(globs))
	for _, g := range globs {
		p, ok, err := Compile(g)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func Compile(raw string) (Pattern, bool, error) {
	pattern := strings.TrimSpace(filepath.ToSlash(raw))
	pattern = strings.TrimPrefix(pattern, "./")
	if pattern == "" {
		return Pattern{}, false, nil
	}

	anchored := strings.HasPrefix(pattern, "/")
	if anchored {
		pattern = strings.TrimPrefix(pattern, "/")
	}
	pattern = strings.TrimPrefix(pattern, "./")
	if pattern == "" {
		return Pattern{}, false, nil
	}

	dirOnly := strings.HasSuffix(pattern, "/")
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		return Pattern{}, false, nil
	}

	hasSlash := strings.Contains(pattern, "/")
	converted := globPatternToRegex(pattern)
	if dirOnly {
		converted += "(?:/.*)?"
	}

	var regex string
	switch {
	case !hasSlash && !dirOnly:
		regex = "^" + converted + "$"
	case anchored:
		regex = "^" + converted + "$"
	default:
		regex = "^(?:.*/)?" + converted + "$"
	}

	compiled, err := regexp.Compile(regex)
	if err != nil {
		return Pattern{}, false, fmt.Errorf("invalid scope pattern %q: %w", raw, err)
	}
	return Pattern{
		raw:          raw,
		basenameOnly: !hasSlash && !dirOnly,
		re:           compiled,
	}, true, nil
}

func MatchAny(patterns []Pattern, relPath string, isDir bool) bool {
	path := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(relPath)), "./")
	path = strings.TrimPrefix(path, "/")
	name := filepath.Base(path)

	for _, p := range patterns {
		target := path
		if p.basenameOnly {
			target = name
		}
		if p.re.MatchString(target) {
			return true
		}
		// Directory patterns should also match the directory itself while walking.
		if isDir && p.re.MatchString(path+"/") {
			return true
		}
	}
	return false
}

func globPatternToRegex(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); {
		ch := pattern[i]
		switch ch {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				if i+2 < len(pattern) && pattern[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 3
					continue
				}
				b.WriteString(".*")
				i += 2
				continue
			}
			b.WriteString("[^/]*")
			i++
		case '?':
			b.WriteString("[^/]")
			i++
		default:
			if strings.ContainsRune(`.+()|[]{}^$\\`, rune(ch)) {
				b.WriteByte('\\')
			}
			b.WriteByte(ch)
			i++
		}
	}
	return b.String()
}
