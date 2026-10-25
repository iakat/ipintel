package ipintel

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
)

// Service is a concurrent HTTP facade over the current database. Swap lets a
// long-running process pick up a rebuilt database without dropping requests.
type Service struct {
	db atomic.Pointer[DB]
}

func NewService(db *DB) *Service {
	s := &Service{}
	s.db.Store(db)
	return s
}

func (s *Service) Swap(db *DB) *DB {
	return s.db.Swap(db)
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /v1/lookup", s.lookup)
	mux.HandleFunc("GET /v1/lookup/{ip}", s.lookup)
	mux.HandleFunc("GET /v1/sources", s.sources)
	mux.HandleFunc("GET /v1/manifest", s.manifest)
	return mux
}

func (s *Service) dbOrError(w http.ResponseWriter) *DB {
	db := s.db.Load()
	if db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not loaded")
		return nil
	}
	return db
}

func (s *Service) lookup(w http.ResponseWriter, r *http.Request) {
	db := s.dbOrError(w)
	if db == nil {
		return
	}
	ip := r.PathValue("ip")
	if ip == "" {
		ip = r.URL.Query().Get("ip")
	}
	if ip == "" {
		writeError(w, http.StatusBadRequest, "missing ip")
		return
	}
	res, err := db.Lookup(ip)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("x-content-type-options", "nosniff")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Service) sources(w http.ResponseWriter, r *http.Request) {
	db := s.dbOrError(w)
	if db == nil {
		return
	}
	w.Header().Set("content-type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(db.Manifest().Sources)
}

func (s *Service) manifest(w http.ResponseWriter, r *http.Request) {
	db := s.dbOrError(w)
	if db == nil {
		return
	}
	w.Header().Set("content-type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(db.Manifest())
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": strings.TrimSpace(msg)})
}
