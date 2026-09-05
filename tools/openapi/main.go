// Command openapi prints the OpenAPI document for the api's router.
//
//	go run ./tools/openapi > docs/openapi.yaml
//
// TestOpenAPIDocIsCurrent fails the build when the committed file is stale.
package main

import (
	"fmt"
	"os"

	"github.com/benlik386/pinkglasses/internal/httpapi"
)

func main() {
	md, _ := os.ReadFile("wiki/API.md")
	fmt.Print(httpapi.OpenAPI(httpapi.RouteTable(), httpapi.PurposesFromDoc(string(md))))
}
