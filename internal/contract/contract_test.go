// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package contract checks every GraphQL operation this module sends against
// the gateway's machine schema, vendored in testdata at the commit pinned in
// gateway-schema.env. A field, argument or type the gateway doesn't have
// fails here instead of as an HTTP 422 GRAPHQL_VALIDATION_FAILED on a box.
package contract

import (
	"encoding/json"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2"
	gqlast "github.com/vektah/gqlparser/v2/ast"
)

// sourceDirs are the module's code roots, relative to this package.
var sourceDirs = []string{"../../cmd", "../../internal"}

// operation is one GraphQL document found in the source.
type operation struct {
	pos  string
	name string
	doc  string
}

func loadSchema(t *testing.T) *gqlast.Schema {
	t.Helper()
	src, err := os.ReadFile("testdata/machine.graphqls")
	if err != nil {
		t.Fatalf("read the vendored schema (run scripts/gateway-schema-fetch.sh): %v", err)
	}
	schema, gerr := gqlparser.LoadSchema(&gqlast.Source{Name: "machine.graphqls", Input: string(src)})
	if gerr != nil {
		t.Fatalf("load the vendored schema: %v", gerr)
	}
	return schema
}

// packageDirs lists every directory under the code roots holding non-test Go
// files.
func packageDirs(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, root := range sourceDirs {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				seen[filepath.Dir(p)] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

// parseDir parses a directory's non-test files and type-checks them only far
// enough to fold string constants (imports are not resolved).
func parseDir(t *testing.T, fset *token.FileSet, dir string) ([]*ast.File, *types.Info) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
	conf := types.Config{Importer: nopImporter{}, Error: func(error) {}, FakeImportC: true}
	_, _ = conf.Check(dir, fset, files, info)
	return files, info
}

type nopImporter struct{}

func (nopImporter) Import(path string) (*types.Package, error) {
	return types.NewPackage(path, filepath.Base(path)), nil
}

// graphQLDoc returns the GraphQL document a string constant holds: an
// operation, or a JSON request body with a "query" member.
func graphQLDoc(s string) (string, bool) {
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, `{"query"`) {
		var body struct {
			Query string `json:"query"`
		}
		if json.Unmarshal([]byte(trimmed), &body) == nil && body.Query != "" {
			return body.Query, true
		}
		return "", false
	}
	for _, kw := range []string{"query ", "query{", "query(", "mutation ", "mutation{", "mutation("} {
		if strings.HasPrefix(trimmed, kw) {
			return trimmed, true
		}
	}
	return "", false
}

// stringConst is the string a constant expression folds to.
func stringConst(info *types.Info, e ast.Expr) (string, bool) {
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

// constOps lists the GraphQL operations held in a package's string constants.
func constOps(fset *token.FileSet, info *types.Info) []operation {
	var ops []operation
	for ident, obj := range info.Defs {
		c, ok := obj.(*types.Const)
		if !ok || c.Val().Kind() != constant.String {
			continue
		}
		if doc, ok := graphQLDoc(constant.StringVal(c.Val())); ok {
			ops = append(ops, operation{pos: fset.Position(ident.Pos()).String(), name: ident.Name, doc: doc})
		}
	}
	return ops
}

// strayCalls lists every call to a gateway client's do method whose query
// argument isn't a constant GraphQL operation.
func strayCalls(fset *token.FileSet, files []*ast.File, info *types.Info) []string {
	var stray []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "do" || len(call.Args) < 3 {
				return true
			}
			q, ok := stringConst(info, call.Args[2])
			if _, isDoc := graphQLDoc(q); !ok || !isDoc {
				stray = append(stray, fset.Position(call.Pos()).String())
			}
			return true
		})
	}
	return stray
}

// collect finds every GraphQL operation held in a string constant, and every
// call to a gateway client's do method whose query is not such a constant.
func collect(t *testing.T) (ops []operation, stray []string) {
	t.Helper()
	fset := token.NewFileSet()
	for _, dir := range packageDirs(t) {
		files, info := parseDir(t, fset, dir)
		ops = append(ops, constOps(fset, info)...)
		stray = append(stray, strayCalls(fset, files, info)...)
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].pos < ops[j].pos })
	return ops, stray
}

func TestEveryOperationMatchesTheGatewaySchema(t *testing.T) {
	schema := loadSchema(t)
	ops, _ := collect(t)
	if len(ops) < 20 {
		t.Fatalf("found %d GraphQL operations; the source scan is broken", len(ops))
	}
	for _, op := range ops {
		if _, errs := gqlparser.LoadQueryWithRules(schema, op.doc, nil); len(errs) > 0 {
			for _, e := range errs {
				t.Errorf("%s %s: %s", op.pos, op.name, e.Message)
			}
		}
	}
}

func TestTheScanFindsTheFindQuery(t *testing.T) {
	ops, _ := collect(t)
	for _, op := range ops {
		if op.name == "findQuery" && strings.Contains(op.doc, "findSecretsForPrincipal") {
			return
		}
	}
	t.Fatal("findQuery not found; the source scan is broken")
}

func TestEveryGatewayCallSendsAConstantOperation(t *testing.T) {
	_, stray := collect(t)
	for _, pos := range stray {
		t.Errorf("%s: the query passed to do is not a GraphQL constant, so the contract test can't check it", pos)
	}
}
