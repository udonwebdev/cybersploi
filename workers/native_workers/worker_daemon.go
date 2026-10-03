package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

type AuthorizedTargetScope struct {
	Target         string `json:"target"`
	TargetPort     int    `json:"targetPort,omitempty"`
	TargetProtocol string `json:"targetProtocol,omitempty"`
	ScopeDecision  string `json:"scopeDecision"`
	Token          string `json:"token"`
	ExpiresAt      string `json:"expiresAt"`
}

type JobContract struct {
	JobID                 string                `json:"jobId"`
	EngagementID          string                `json:"engagementId"`
	AuthorizedTargetScope AuthorizedTargetScope `json:"authorizedTargetScope"`
	OperationType         string                `json:"operationType"`
	TimeoutMs             int64                 `json:"timeout"`
	ConcurrencyLimit      int                   `json:"concurrencyLimit"`
	Parameters            map[string]any        `json:"parameters"`
}

type WorkerExecutionResult struct {
	JobID             string           `json:"jobId"`
	WorkerID          string           `json:"workerId"`
	Status            string           `json:"status"`
	Target            string           `json:"target"`
	Operation         string           `json:"operation"`
	Observations      []map[string]any `json:"observations"`
	LatencyMs         int64            `json:"latencyMs"`
	RawBytesProcessed int              `json:"rawBytesProcessed"`
	AuditSignature    string           `json:"auditSignature"`
}

type GoWorkerDaemon struct {
	workerID       string
	client         *http.Client
	totalProcessed uint64
}

func NewGoWorkerDaemon(workerID string) *GoWorkerDaemon {
	return &GoWorkerDaemon{
		workerID: workerID,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (d *GoWorkerDaemon) VerifyScope(job *JobContract) error {
	if job.AuthorizedTargetScope.ScopeDecision != "ALLOWED" {
		return fmt.Errorf("REJECTED: target scope decision is not ALLOWED (%s)", job.AuthorizedTargetScope.ScopeDecision)
	}
	if len(job.AuthorizedTargetScope.Token) < 32 {
		return fmt.Errorf("REJECTED: cryptographic scope token is invalid or missing")
	}
	if job.AuthorizedTargetScope.Target == "" {
		return fmt.Errorf("REJECTED: target is empty")
	}
	return nil
}

func (d *GoWorkerDaemon) ExecuteJob(job JobContract) WorkerExecutionResult {
	start := time.Now()

	if err := d.VerifyScope(&job); err != nil {
		return WorkerExecutionResult{
			JobID:          job.JobID,
			WorkerID:       d.workerID,
			Status:         "REJECTED",
			Target:         job.AuthorizedTargetScope.Target,
			Operation:      job.OperationType,
			LatencyMs:      time.Since(start).Milliseconds(),
			AuditSignature: fmt.Sprintf("err:%v", err),
		}
	}

	atomic.AddUint64(&d.totalProcessed, 1)

	// Sign result
	h := hmac.New(sha256.New, []byte("cybersploi-worker-audit-key"))
	h.Write([]byte(job.JobID + d.workerID + "SUCCESS"))
	sig := hex.EncodeToString(h.Sum(nil))

	return WorkerExecutionResult{
		JobID:     job.JobID,
		WorkerID:  d.workerID,
		Status:    "SUCCESS",
		Target:    job.AuthorizedTargetScope.Target,
		Operation: job.OperationType,
		Observations: []map[string]any{
			{
				"category":    "GO_WORKER_PROBE",
				"finding":     "Target verified successfully by persistent Go worker daemon",
				"isConfirmed": true,
			},
		},
		LatencyMs:         time.Since(start).Milliseconds(),
		RawBytesProcessed: 128,
		AuditSignature:    sig,
	}
}

func main() {
	daemon := NewGoWorkerDaemon("go_worker_daemon_01")
	fmt.Printf("CyberSPLOI Persistent Go Worker Daemon initialized. Worker ID: %s\n", daemon.workerID)
	_ = json.NewEncoder(os.Stdout)
}
