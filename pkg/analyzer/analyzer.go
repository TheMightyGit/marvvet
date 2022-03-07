package analyzer

import (
	"go/ast"

	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"golang.org/x/tools/go/analysis"
)

var Analyzer = &analysis.Analyzer{
	Name:     "marvvet",
	Doc:      "Checks that Marv300 codebases use only whitelisted imports.",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

var importWhitelist = map[string]struct{}{
	`"github.com/TheMightyGit/marv/marvlib"`:   {},
	`"github.com/TheMightyGit/marv/marvtypes"`: {},
	`"github.com/TheMightyGit/cart/cartridge"`: {},
	`"image"`:     {},
	`"strings"`:   {},
	`"math/rand"`: {},
	`"math"`:      {},
	`"sort"`:      {},
	`"strconv"`:   {},
	`"embed"`:     {},
	`"time"`:      {},
	`"fmt"`:       {},
}

func run(pass *analysis.Pass) (interface{}, error) {
	inspector := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{
		(*ast.ImportSpec)(nil),
	}

	inspector.Preorder(nodeFilter, func(node ast.Node) {
		importSpec := node.(*ast.ImportSpec)

		if _, found := importWhitelist[importSpec.Path.Value]; found {
			return
		}

		pass.Reportf(node.Pos(), "import of external package '%s' is not whitelisted", importSpec.Path.Value)
	})

	return nil, nil
}
