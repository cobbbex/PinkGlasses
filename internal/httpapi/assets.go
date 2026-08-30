package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/benlik386/asm/internal/search"
	"github.com/benlik386/asm/internal/store"
)

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListDomains(r.Context(), scopeID, r.URL.Query().Get("q"), 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) domainGraph(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	edges, err := s.st.DomainGraph(r.Context(), scopeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, buildGraph(edges))
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	list, err := s.st.ListHosts(r.Context(), scopeID, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) hostServices(w http.ResponseWriter, r *http.Request) {
	ipID, err := uuid.Parse(chi.URLParam(r, "ipID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad host id")
		return
	}
	list, err := s.st.HostServices(r.Context(), ipID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// searchGlobal searches across every company (or one, via ?scope=), Shodan-style.
func (s *Server) searchGlobal(w http.ResponseWriter, r *http.Request) {
	compiled, err := search.Compile(r.URL.Query().Get("q"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "query error: "+err.Error())
		return
	}
	var scopeID *uuid.UUID
	if v := r.URL.Query().Get("scope"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			scopeID = &id
		}
	}
	results, err := s.st.SearchGlobal(r.Context(), scopeID, compiled.Where, compiled.Args, 300)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, results)
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	scopeID, err := uuid.Parse(chi.URLParam(r, "scopeID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad scope id")
		return
	}
	compiled, err := search.Compile(r.URL.Query().Get("q"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "query error: "+err.Error())
		return
	}
	results, err := s.st.Search(r.Context(), scopeID, compiled.Where, compiled.Args, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, results)
}

// buildGraph turns domain->ip edges into a Cytoscape-style node/edge payload.
func buildGraph(edges []store.GraphEdge) map[string]any {
	nodes := map[string]map[string]any{}
	var links []map[string]any
	for _, e := range edges {
		dID := "d:" + e.Domain
		iID := "i:" + e.IP
		nodes[dID] = map[string]any{"id": dID, "label": e.Domain, "type": "domain"}
		nodes[iID] = map[string]any{"id": iID, "label": e.IP, "type": "ip"}
		links = append(links, map[string]any{"source": dID, "target": iID, "via": e.Via})
	}
	var nodeList []map[string]any
	for _, n := range nodes {
		nodeList = append(nodeList, n)
	}
	return map[string]any{"nodes": nodeList, "edges": links}
}
