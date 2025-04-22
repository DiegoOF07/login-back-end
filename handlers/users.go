package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"loginapp/models"
	"net/http"
)

// --- Nuevo Handler para Perfil ---
// (Podría ir en users.go o un nuevo profile.go)
func GetUserProfileHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
         // Obtener userID del contexto (inyectado por el middleware)
         userID, ok := r.Context().Value("userID").(int)
         if !ok || userID == 0 {
             http.Error(w, `{"error": "No se pudo obtener ID de usuario del token"}`, http.StatusInternalServerError)
             return
         }

         // Ahora usar este userID para buscar los datos del perfil
         var userResp models.LoginSuccessData
         err := db.QueryRow("SELECT id, username FROM users WHERE id = ?", userID).Scan(&userResp.UserID, &userResp.Username)
         if err != nil {
             // ... (manejo de error: 404 si no se encuentra, 500 otros) ...
             if err == sql.ErrNoRows {
                 http.Error(w, `{"error": "Usuario del token no encontrado"}`, http.StatusNotFound)
             } else {
                 log.Printf("Error consultando perfil para user %d: %v", userID, err)
                 http.Error(w, `{"error": "Error interno del servidor"}`, http.StatusInternalServerError)
             }
             return
         }

         w.Header().Set("Content-Type", "application/json")
         json.NewEncoder(w).Encode(userResp)
    }
}