// Package config loads runtime configuration from the environment.
// Every binary constructs the subset it needs; there is no config file in the image.
package config

import (
	"os"
	"strconv"
	"time"
)

// API holds configuration for the user-facing api binary.
type API struct {
	DatabaseURL string
	Addr        string
	S3          S3
}

// Gateway holds configuration for the agent-facing gateway binary.
type Gateway struct {
	DatabaseURL      string
	Addr             string
	PublicGatewayURL string
	S3               S3
	LeaseTTL         time.Duration
	// LocalBootstrapToken is shared with local worker containers so they can
	// self-enroll; leave empty to disable local self-enrollment entirely.
	LocalBootstrapToken string
}

// Scheduler holds configuration for the scheduler binary.
type Scheduler struct {
	DatabaseURL string
	Tick        time.Duration
}

// Worker holds configuration for a scan box.
type Worker struct {
	GatewayURL     string
	CredentialFile string
	Name           string
	MaxConcurrency int
}

// S3 configures the object-storage backend (S3 or MinIO).
type S3 struct {
	Endpoint  string
	Bucket    string
	AccessKey string
	SecretKey string
	Region    string
}

func s3FromEnv() S3 {
	return S3{
		Endpoint:  env("ASM_S3_ENDPOINT", "http://localhost:9000"),
		Bucket:    env("ASM_S3_BUCKET", "asm-artifacts"),
		AccessKey: env("ASM_S3_ACCESS_KEY", "minioadmin"),
		SecretKey: env("ASM_S3_SECRET_KEY", "minioadmin"),
		Region:    env("ASM_S3_REGION", "us-east-1"),
	}
}

// LoadAPI builds API config from the environment.
func LoadAPI() API {
	return API{
		DatabaseURL: env("ASM_DATABASE_URL", "postgres://asm:asm@localhost:5432/asm?sslmode=disable"),
		Addr:        env("ASM_API_ADDR", ":8080"),
		S3:          s3FromEnv(),
	}
}

// LoadGateway builds Gateway config from the environment.
func LoadGateway() Gateway {
	return Gateway{
		DatabaseURL:      env("ASM_DATABASE_URL", "postgres://asm:asm@localhost:5432/asm?sslmode=disable"),
		Addr:             env("ASM_GATEWAY_ADDR", ":8090"),
		PublicGatewayURL: env("ASM_PUBLIC_GATEWAY_URL", "http://localhost:8090"),
		S3:               s3FromEnv(),
		LeaseTTL:         envDuration("ASM_LEASE_TTL", 2*time.Minute),
		LocalBootstrapToken: env("ASM_LOCAL_BOOTSTRAP_TOKEN", ""),
	}
}

// LoadScheduler builds Scheduler config from the environment.
func LoadScheduler() Scheduler {
	return Scheduler{
		DatabaseURL: env("ASM_DATABASE_URL", "postgres://asm:asm@localhost:5432/asm?sslmode=disable"),
		Tick:        envDuration("ASM_SCHED_TICK", 15*time.Second),
	}
}

// LoadWorker builds Worker config from the environment.
func LoadWorker() Worker {
	return Worker{
		GatewayURL:     env("ASM_GATEWAY_URL", "http://localhost:8090"),
		CredentialFile: env("ASM_WORKER_CREDENTIAL_FILE", "./credential"),
		// empty by default so each replica registers under its container
		// hostname; scaled local workers stay distinguishable in the fleet list
		Name:           env("ASM_WORKER_NAME", ""),
		MaxConcurrency: envInt("ASM_WORKER_MAX_CONCURRENCY", 8),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
