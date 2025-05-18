package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Installation struct {
	ID int64 `json:"id"`
}

type WorkflowEvent struct {
	Installation Installation `json:"installation"`
}

var db *pgxpool.Pool

func main() {
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("Missing DATABASE_URL environment variable")
	}

	var err error
	db, err = pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	defer db.Close()

	http.HandleFunc("/webhook", webhookHandler)

	port := getEnv("PORT", "8080")
	log.Printf("Starting server on :%s...", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if secret == "" {
		http.Error(w, "Webhook secret not configured", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Cannot read body", http.StatusBadRequest)
		return
	}

	signature := r.Header.Get("X-Hub-Signature-256")
	if !validateSignature(signature, body, []byte(secret)) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "workflow_run" || eventType == "workflow_job" {
		var payload WorkflowEvent
		if err := json.Unmarshal(body, &payload); err != nil {
			log.Printf("Failed to parse JSON: %v", err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		log.Printf("Received %s event from installation ID: %d", eventType, payload.Installation.ID)

		if err := saveEvent(r.Context(), payload.Installation.ID, eventType, body); err != nil {
			log.Printf("Failed to save event: %v", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	} else {
		log.Printf("Ignored event: %s", eventType)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Webhook received")
}

func saveEvent(ctx context.Context, installationID int64, eventType string, payload []byte) error {
	_, err := db.Exec(ctx,
		`INSERT INTO events (installation_id, event_type, payload, received_at)
		 VALUES ($1, $2, $3, $4)`,
		installationID, eventType, payload, time.Now(),
	)
	return err
}

func validateSignature(signature string, body []byte, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

