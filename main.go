package main

import (
    "log"
    "net/http"

	"loginapp/handlers"
    "loginapp/utils"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
)

func main() {
    // Conectar a la base de datos
    db, err := setupDatabase("./users.db")
    if err != nil {
        log.Fatal("CRITICAL: No se pudo conectar a la base de datos:", err)
    }
    defer db.Close() // Asegurar que se cierre al final

    // Crear router Chi
    r := chi.NewRouter()

    // Middlewares
    r.Use(middleware.Logger)    // Loggea cada request
    r.Use(middleware.Recoverer) // Recupera de panics
    r.Use(configureCORS())      // Aplica nuestra configuración CORS

     // --- Rutas Públicas ---
     r.Route("/auth", func(r chi.Router) {
        r.Post("/register", handlers.PostRegisterHandler(db)) // Mover register aquí
        r.Post("/login", handlers.PostLoginHandler(db))    // Mover login aquí
   })
   r.Get("/", func(w http.ResponseWriter, r *http.Request) { /* ... */ })

   // --- Rutas Protegidas ---
   r.Group(func(r chi.Router) {
    r.Use(utils.JwtAuthMiddleware(db))

    // Rutas que requieren token válido
    r.Post("/auth/logout", handlers.PostLogoutHandler(db)) // Mover logout aquí
    r.Get("/users/profile", handlers.GetUserProfileHandler(db)) // Nueva ruta para perfil
    // La ruta /users/{userID} podría seguir siendo pública o protegerse también
    // r.Get("/users/{userID}", getUserHandler(db)) // Ejemplo si se protege
    })

    // Iniciar servidor
    port := ":3000"
    log.Printf("Servidor escuchando en puerto %s", port)
    log.Fatal(http.ListenAndServe(port, r))
}