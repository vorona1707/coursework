package main 

import (
	"log"
	"net/http"
)

func main() {
	dir := http.Dir("./static")

	fs := http.FileServer(dir)

	mux := http.NewServeMux()

	mux.Handle("/", fs)
	mux.Handle("/reg.html", fs)
	
	log.Printf("=ПОШЛО ДОБРО=")

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal(err)
	}
}

