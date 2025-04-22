package utils

import (
    "context"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

var jwtSecretKey = []byte("secret1234")

type CustomClaims struct {
    UserID int `json:"user_id"`
    jwt.RegisteredClaims
}

func GenerateJWT(userID int) (string, time.Time, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &CustomClaims{
        UserID: userID,
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   strconv.Itoa(userID),
            ExpiresAt: jwt.NewNumericDate(expirationTime),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtSecretKey)
    if err != nil {
        return "", time.Time{}, err
    }
    return tokenString, expirationTime, nil
}

func HashToken(token string) string {
    hasher := sha256.New()
    hasher.Write([]byte(token))
    return hex.EncodeToString(hasher.Sum(nil))
}

func StoreToken(db *sql.DB, userID int, token string, expiresAt time.Time) error {
    tokenHash := HashToken(token)
    _, err := db.Exec("INSERT INTO active_tokens(user_id, token_hash, expires_at) VALUES(?, ?, ?)", 
        userID, tokenHash, expiresAt)
    if err != nil {
        return fmt.Errorf("error guardando token: %w", err)
    }
    return nil
}

func InvalidateToken(db *sql.DB, token string) error {
    tokenHash := HashToken(token)
    result, err := db.Exec("DELETE FROM active_tokens WHERE token_hash = ?", tokenHash)
    if err != nil {
        return fmt.Errorf("error invalidando token: %w", err)
    }
    
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        log.Printf("Token no encontrado o ya invalidado (hash: %s...)", tokenHash[:10])
    } else {
        log.Printf("Token invalidado exitosamente (hash: %s...)", tokenHash[:10])
    }
    return nil
}

func cleanupExpiredToken(db *sql.DB, tokenString string) error {
    tokenHash := HashToken(tokenString)
    _, err := db.Exec("DELETE FROM active_tokens WHERE token_hash = ?", tokenHash)
    if err != nil && err != sql.ErrNoRows {
        return fmt.Errorf("error eliminando token expirado: %w", err)
    }
    log.Printf("Token expirado limpiado de DB (hash: %s...)", tokenHash[:10])
    return nil
}

func validateTokenAndGetUserID(db *sql.DB, tokenString string) (int, error) {
    claims := &jwt.RegisteredClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
        }
        return jwtSecretKey, nil
    })

    if err != nil {
        if errors.Is(err, jwt.ErrTokenExpired) {
            log.Println("Token expirado detectado:", err)
            go func() { 
                errClean := cleanupExpiredToken(db, tokenString)
                if errClean != nil {
                    log.Printf("Error limpiando token expirado de DB: %v", errClean)
                }
            }()
        }
        return 0, fmt.Errorf("error parseando token: %w", err)
    }

    if !token.Valid {
        return 0, errors.New("token inválido")
    }

    tokenHash := HashToken(tokenString)
    var dbUserID int
    var expiresAt time.Time
    err = db.QueryRow("SELECT user_id, expires_at FROM active_tokens WHERE token_hash = ?", tokenHash).Scan(&dbUserID, &expiresAt)
    if err != nil {
        if err == sql.ErrNoRows {
            return 0, errors.New("token no encontrado o inactivo en DB")
        }
        return 0, fmt.Errorf("error consultando token en DB: %w", err)
    }

    if time.Now().After(expiresAt) {
        go func() {
            errClean := cleanupExpiredToken(db, tokenString)
            if errClean != nil {
                log.Printf("Error limpiando token expirado de DB (check secundario): %v", errClean)
            }
        }()
        return 0, errors.New("token expirado (según DB)")
    }

    // Obtener userID del subject
    if claims.Subject == "" {
        return 0, errors.New("token no contiene subject (userID)")
    }

    var userID int
    _, err = fmt.Sscan(claims.Subject, &userID)
    if err != nil {
        return 0, fmt.Errorf("error convirtiendo subject a userID: %w", err)
    }

    if userID != dbUserID {
        return 0, errors.New("discrepancia de UserID entre token y DB")
    }

    return userID, nil
}

func JwtAuthMiddleware(db *sql.DB) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Falta header de autorización", http.StatusUnauthorized)
                return
            }

            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
                http.Error(w, "Header de autorización mal formado (se espera 'Bearer token')", http.StatusUnauthorized)
                return
            }

            tokenString := parts[1]
            userID, err := validateTokenAndGetUserID(db, tokenString)
            if err != nil {
                log.Printf("Error validando token: %v", err)
                http.Error(w, "Token inválido o expirado", http.StatusUnauthorized)
                return
            }

            ctx := context.WithValue(r.Context(), "userID", userID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}