package analyzer

import (
	"fmt"
	"go/ast"
	"os"

	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"golang.org/x/tools/go/analysis"

	"golang.org/x/mod/modfile"
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
	// `"github.com/TheMightyGit/cart/cartridge"`: {}, <-- now got from go.mod file
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

	// playing with mod stuff
	data, err := os.ReadFile("go.mod")
	if err != nil {
		panic(err)
	}
	modFile, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(modFile)
	fmt.Println(modFile.Module.Mod)
	importWhitelist[`"`+modFile.Module.Mod.String()+`"`] = struct{}{}
	importWhitelist[`"`+modFile.Module.Mod.String()+"/cartridge"+`"`] = struct{}{}
	/// end mod stuff

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
