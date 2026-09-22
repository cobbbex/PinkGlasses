package httpapi

import (
	"net/http"
)

// The MCP page in the app: what the built-in MCP server offers and the skill
// that teaches a client to use it. The server itself is mounted at /mcp by
// cmd/api, which also supplies these descriptions — httpapi does not import
// the MCP package, whose tests walk this router.

// MCPTool describes one tool for the page.
type MCPTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ReadOnly    bool   `json:"read_only"`
	Destructive bool   `json:"destructive"`
}

// MCPProvider is what cmd/api hands the router: the tool list and the skill.
type MCPProvider interface {
	Tools() []MCPTool
	SkillZip() ([]byte, error)
	AllowsDeleteCompany() bool
}

// SetMCP installs the provider. Without one the routes answer 404, so an api
// built without the MCP server does not pretend to have one.
func (s *Server) SetMCP(p MCPProvider) { s.mcp = p }

// mcpSettings lists the tools the MCP server exposes, for the page to show.
func (s *Server) mcpSettings(w http.ResponseWriter, r *http.Request) {
	if s.mcp == nil {
		writeErr(w, http.StatusNotFound, "no MCP server in this build")
		return
	}
	tools := s.mcp.Tools()
	if tools == nil {
		tools = []MCPTool{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":                 "/mcp",
		"tools":                tools,
		"allow_delete_company": s.mcp.AllowsDeleteCompany(),
	})
}

// mcpSkill serves the skill as a zip, to unpack into a skills folder.
func (s *Server) mcpSkill(w http.ResponseWriter, r *http.Request) {
	if s.mcp == nil {
		writeErr(w, http.StatusNotFound, "no MCP server in this build")
		return
	}
	data, err := s.mcp.SkillZip()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="pinkglasses-skill.zip"`)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}
