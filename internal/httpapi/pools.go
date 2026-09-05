package httpapi

import "net/http"

// listPools returns the pools a run may choose as its remote exit, with live
// worker counts so the launch dialog can say which ones can actually run
// something.
func (s *Server) listPools(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListExitPools(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}
