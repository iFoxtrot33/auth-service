package swagger

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger"
)

func SetupSwagger(router *http.ServeMux) {

	router.HandleFunc("GET /docs/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "docs/swagger.json")
	})

	router.HandleFunc("GET /docs/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		handler := httpSwagger.Handler(
			httpSwagger.URL("/docs/swagger.json"),
		)
		handler.ServeHTTP(w, r)
	})

	router.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/", http.StatusFound)
	})
}
