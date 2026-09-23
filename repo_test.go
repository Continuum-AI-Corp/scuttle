package scuttle

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Tests that keep the repository's claims about itself true. Each of these
// drifted once already: CI ran seven of eight fuzz targets, ATTACK.md said
// "five", and every README ended in the middle of a sentence.

// fuzzTargets derives the list from the source, so a new target is covered
// the day it is written rather than the day someone remembers the list.
func fuzzTargets(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*_test.go")
	var out []string
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Fuzz") {
				out = append(out, fn.Name.Name)
			}
		}
	}
	sort.Strings(out)
	if len(out) < 8 {
		t.Fatalf("found only %d fuzz targets; the scan is broken", len(out))
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCI_RunsEveryFuzzTargetInBothJobs(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	smoke := section(t, ci, "fuzz-smoke:", "fuzz-long:")
	long := section(t, ci, "fuzz-long:", "\n  govulncheck:")
	for _, name := range fuzzTargets(t) {
		word := regexp.MustCompile(`\b` + name + `\b`)
		if !word.MatchString(smoke) {
			t.Errorf("fuzz-smoke does not run %s", name)
		}
		if !word.MatchString(long) {
			t.Errorf("fuzz-long does not run %s", name)
		}
	}
}

func section(t *testing.T, s, from, to string) string {
	t.Helper()
	i := strings.Index(s, from)
	if i < 0 {
		t.Fatalf("ci.yml has no %q", from)
	}
	rest := s[i:]
	if j := strings.Index(rest, to); j > 0 {
		return rest[:j]
	}
	t.Fatalf("ci.yml has no %q after %q", to, from)
	return ""
}

// Third-party actions are pinned to a commit, not a movable tag: a tag can be
// repointed by whoever controls the action's repository.
func TestCI_PinsEveryActionToACommit(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	uses := regexp.MustCompile(`(?m)uses:\s*(\S+)`).FindAllStringSubmatch(ci, -1)
	if len(uses) == 0 {
		t.Fatal("no actions found; the scan is broken")
	}
	pinned := regexp.MustCompile(`^[\w.-]+/[\w.-]+@[0-9a-f]{40}$`)
	for _, u := range uses {
		if !pinned.MatchString(u[1]) {
			t.Errorf("action not pinned to a commit SHA: %s", u[1])
		}
	}
}

func TestCI_RunsGovulncheck(t *testing.T) {
	if !regexp.MustCompile(`govulncheck(@v\d+\.\d+\.\d+)? \./\.\.\.`).MatchString(readFile(t, ".github/workflows/ci.yml")) {
		t.Fatal("ci.yml does not run govulncheck")
	}
}

func TestAttackMd_ListsEveryFuzzTargetAndCountsThemRight(t *testing.T) {
	doc := readFile(t, "ATTACK.md")
	targets := fuzzTargets(t)
	for _, name := range targets {
		if !strings.Contains(doc, "`"+name+"`") {
			t.Errorf("ATTACK.md does not list %s", name)
		}
	}
	// A spelled-out count that disagrees with the table is how "Five fuzz
	// targets" sat above a table of eight.
	words := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve"}
	m := regexp.MustCompile(`(?i)\b(\w+) fuzz targets\b`).FindAllStringSubmatch(doc, -1)
	for _, g := range m {
		for n, w := range words {
			if strings.EqualFold(g[1], w) && n != len(targets) {
				t.Errorf("ATTACK.md says %q; there are %d", g[0], len(targets))
			}
		}
	}
}

// Every README ends where it means to. All seven once stopped mid-sentence.
func TestReadmes_AreNotTruncated(t *testing.T) {
	files, _ := filepath.Glob("README*.md")
	if len(files) < 7 {
		t.Fatalf("found %d READMEs", len(files))
	}
	for _, f := range files {
		body := strings.TrimSpace(readFile(t, f))
		lines := strings.Split(body, "\n")
		last := strings.TrimSpace(lines[len(lines)-1])
		if !regexp.MustCompile("([.!?)`>|*]|[。！？）]|```)$").MatchString(last) {
			t.Errorf("%s ends mid-sentence: %q", f, last)
		}
	}
}

// Each translation is actually a translation: code, identifiers, tables and
// diagrams may stay in English, but prose may not. The measure is the share
// of the translation's prose lines that appear verbatim in the English README;
// before this test the six "translations" were 85-99% English.
func TestReadmes_TranslationsAreTranslated(t *testing.T) {
	english := map[string]bool{}
	for _, l := range proseLines(readFile(t, "README.md")) {
		english[l] = true
	}
	files, _ := filepath.Glob("README.*.md")
	for _, f := range files {
		lines := proseLines(readFile(t, f))
		if len(lines) < 50 {
			t.Errorf("%s has only %d prose lines; the scan is broken or the file is a stub", f, len(lines))
			continue
		}
		same := 0
		for _, l := range lines {
			if english[l] {
				same++
			}
		}
		if share := float64(same) / float64(len(lines)); share > 0.10 {
			t.Errorf("%s: %d of %d prose lines (%.0f%%) are the English text", f, same, len(lines), share*100)
		}
	}
}

// proseLines returns the lines of a Markdown document that are sentences:
// outside code fences, not tables, HTML, badges or headings of code, and
// containing at least two words.
func proseLines(doc string) []string {
	var out []string
	inCode := false
	twoWords := regexp.MustCompile(`\pL{3,}.*\s.*\pL{3,}`)
	for _, l := range strings.Split(doc, "\n") {
		s := strings.TrimSpace(l)
		if strings.HasPrefix(s, "```") {
			inCode = !inCode
			continue
		}
		if inCode || s == "" || !twoWords.MatchString(s) {
			continue
		}
		if strings.HasPrefix(s, "|") || strings.HasPrefix(s, "<") || strings.HasPrefix(s, "[!") || strings.HasPrefix(s, "- [`") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Every relative link in every Markdown file points at a file that exists.
// The translations once linked ../LICENSE and ../README.md from the root.
func TestMarkdown_RelativeLinksResolve(t *testing.T) {
	files, _ := filepath.Glob("*.md")
	link := regexp.MustCompile(`(?:\]\(|href=")([^)"#\s]+)`)
	checked := 0
	for _, f := range files {
		for _, m := range link.FindAllStringSubmatch(readFile(t, f), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			checked++
			if _, err := os.Stat(filepath.Join(filepath.Dir(f), target)); err != nil {
				t.Errorf("%s links to %s, which does not exist", f, target)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("checked only %d links; the scan is broken", checked)
	}
}

// Internal references from the project scuttle was extracted from. They
// point at documents and systems a public reader cannot see.
func TestRepo_HasNoReferencesToThePrivateParentProject(t *testing.T) {
	banned := []string{
		"REQUESTLOG_ENCRYPTION_ERASURE_PLAN",
		"pkg/scuttle",
		"mongodump",
		"WiredTiger",
		"request_body_size",
		"parent project",
	}
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == ".git" || path == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if path == "repo_test.go" || !regexp.MustCompile(`\.(go|md|yml)$`).MatchString(path) {
			return nil
		}
		body := readFile(t, path)
		for _, b := range banned {
			if strings.Contains(body, b) {
				t.Errorf("%s mentions %q", path, b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRepo_HasTheFilesAnOpenSourceCryptoLibraryNeeds(t *testing.T) {
	for _, f := range []string{"LICENSE", "SECURITY.md", "ATTACK.md", "SPEC.md", "CHANGELOG.md", "CONTRIBUTING.md", "testdata/vectors.json"} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("missing %s", f)
		}
	}
}

// githubSlug is GitHub's heading-anchor rule: lowercase, drop everything that
// is not a letter, digit, space, hyphen or underscore, spaces to hyphens, and
// "-1", "-2"... for repeats.
func githubAnchors(doc string) map[string]bool {
	out := map[string]bool{}
	seen := map[string]int{}
	inCode := false
	keep := regexp.MustCompile(`[^\p{L}\p{N}\p{M} _-]`)
	for _, l := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			inCode = !inCode
			continue
		}
		if inCode || !strings.HasPrefix(l, "#") {
			continue
		}
		h := strings.TrimSpace(strings.TrimLeft(l, "#"))
		slug := strings.ReplaceAll(keep.ReplaceAllString(strings.ToLower(h), ""), " ", "-")
		if n := seen[slug]; n > 0 {
			out[slug+"-"+strconv.Itoa(n)] = true
		} else {
			out[slug] = true
		}
		seen[slug]++
	}
	return out
}

func TestMarkdown_InPageAnchorsResolve(t *testing.T) {
	files, _ := filepath.Glob("*.md")
	ref := regexp.MustCompile(`\]\(#([^)\s]+)\)`)
	checked := 0
	for _, f := range files {
		doc := readFile(t, f)
		anchors := githubAnchors(doc)
		for _, m := range ref.FindAllStringSubmatch(doc, -1) {
			checked++
			if !anchors[m[1]] {
				t.Errorf("%s links to #%s, which is not a heading in it", f, m[1])
			}
		}
	}
	if checked < 7 {
		t.Fatalf("checked only %d anchors; the scan is broken", checked)
	}
}

// securityMailbox is where findings go. Stated once here so the test and the
// docs cannot disagree about it.
const securityMailbox = "security@orcarouter.ai"

func TestSecurityMd_NamesTheSecurityMailbox(t *testing.T) {
	if !strings.Contains(readFile(t, "SECURITY.md"), securityMailbox) {
		t.Fatalf("SECURITY.md does not give %s as a reporting channel", securityMailbox)
	}
}

// No personal address ships in the tree: the only mailbox a reader should
// find is the project's own.
func TestRepo_PublishesNoPersonalEmail(t *testing.T) {
	email := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	allowed := map[string]bool{securityMailbox: true}
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		for _, m := range email.FindAllString(readFile(t, path), -1) {
			if !allowed[m] {
				t.Errorf("%s contains the address %s", path, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
