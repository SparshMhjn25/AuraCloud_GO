package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"auracloud/pkg/api"
	"auracloud/pkg/chunker"
	"auracloud/pkg/crypto"
	"auracloud/pkg/db"
	"auracloud/pkg/network"
	"auracloud/pkg/storage"
	"auracloud/pkg/utils"

	"github.com/google/uuid"
)

// Architectural Concept: Milestone 5 Production Release
//
// Milestone 5 embeds the web UI dashboard, auto-launches the system browser,
// and compiles into a single production executable `auracloud.exe`.

func main() {
	benchmark := flag.Bool("benchmark", false, "run the storage pipeline benchmark")
	flag.Parse()
	if *benchmark {
		runBenchmark()
		return
	}
	fmt.Println("==================================================================")
	fmt.Println("             AURACLOUD - PEER-TO-PEER BACKUP SYSTEM              ")
	fmt.Println("   Milestone 5: Web UI Dashboard, Auto-Browser & Single Binary    ")
	fmt.Println("==================================================================")

	dbPath := db.DefaultDBPath
	manifestDB, err := db.InitDB(dbPath)
	if err != nil {
		fmt.Printf("FATAL: Failed to initialize SQLite database at %s: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer manifestDB.Close()

	fmt.Printf("[SYSTEM] Embedded SQLite Manifest DB initialized cleanly at: %s\n", dbPath)

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\nSelect an action:")
		fmt.Println("  [1] Run Automated End-to-End Pipeline Verification")
		fmt.Println("  [2] Process a Custom File (Chunk, Encrypt, Register in DB & Reassemble)")
		fmt.Println("  [3] List Registered Files from SQLite Database")
		fmt.Println("  [4] Start Local REST API Server (http://localhost:8080)")
		fmt.Println("  [5] Start P2P Tailscale Mesh Node & API Server (WireGuard Encrypted)")
		fmt.Println("  [6] Exit")
		fmt.Print("\nEnter choice (1-6): ")

		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			return
		}

		choice := strings.TrimSpace(input)

		switch choice {
		case "1":
			runAutomatedVerification(manifestDB)
		case "2":
			fmt.Print("Enter path to file: ")
			filePathInput, _ := reader.ReadString('\n')
			filePath := strings.TrimSpace(filePathInput)
			if filePath == "" {
				fmt.Println("Invalid file path.")
				continue
			}
			processCustomFile(manifestDB, filePath)
		case "3":
			listFilesFromDB(manifestDB)
		case "4":
			startLocalAPIServer(manifestDB)
		case "5":
			startMeshP2PNode(manifestDB)
		case "6":
			fmt.Println("Exiting AuraCloud Milestone 4 CLI. Goodbye!")
			return
		default:
			fmt.Println("Invalid choice, please enter 1–6.")
		}
	}
}

// runBenchmark is opt-in so normal interactive and server startup is unchanged.
func runBenchmark() {
	root, err := os.MkdirTemp("", "auracloud-benchmark-*")
	if err != nil {
		fmt.Println("benchmark:", err)
		return
	}
	defer os.RemoveAll(root)
	database, err := db.InitDB(filepath.Join(root, "manifest.db"))
	if err != nil {
		fmt.Println("benchmark:", err)
		return
	}
	defer database.Close()
	key, err := crypto.GenerateMasterKey()
	if err != nil {
		fmt.Println("benchmark:", err)
		return
	}
	fmt.Println("Trials: 5 per payload; throughput uses MiB/s. Peak memory reports maximum Go heap allocation.")
	for _, sizeMB := range []int{10, 50, 150, 500} {
		var readT, encT, dbT, restoreT []float64
		var peak uint64
		for trial := 0; trial < 5; trial++ {
			path := filepath.Join(root, "payload.dat")
			if err := generateSampleFile(path, int64(sizeMB)*1024*1024); err != nil {
				fmt.Println("benchmark:", err)
				return
			}
			t := time.Now()
			chunks, err := chunker.ChunkFile(path, chunker.DefaultChunkSize)
			readT = append(readT, time.Since(t).Seconds())
			if err != nil {
				fmt.Println(err)
				return
			}
			fileID := uuid.New().String()
			records := make([]db.ChunkRecord, 0, len(chunks))
			encrypted := make([][]byte, len(chunks))
			nonces := make([][]byte, len(chunks))
			t = time.Now()
			for i, c := range chunks {
				encrypted[i], nonces[i], err = crypto.EncryptChunkWithAAD(c.Data, key, []byte(fmt.Sprintf("%s:%d", fileID, i)))
				if err != nil {
					fmt.Println(err)
					return
				}
				records = append(records, db.ChunkRecord{FileID: fileID, ChunkIndex: i, CID: crypto.GenerateCID(encrypted[i]), NonceHex: hex.EncodeToString(nonces[i]), ChunkSize: c.Size})
			}
			encT = append(encT, time.Since(t).Seconds())
			t = time.Now()
			err = database.RegisterFile(db.FileRecord{ID: fileID, FileName: "benchmark", FileSize: int64(sizeMB) * 1024 * 1024, MimeType: "application/octet-stream", TotalChunks: len(chunks), CreatedAt: time.Now()}, records)
			dbT = append(dbT, float64(time.Since(t).Milliseconds()))
			if err != nil {
				fmt.Println(err)
				return
			}
			t = time.Now()
			restoredPath := filepath.Join(root, "restored.dat")
			restored, createErr := os.Create(restoredPath)
			if createErr != nil {
				fmt.Println(createErr)
				return
			}
			for i := range chunks {
				plain, e := crypto.DecryptChunkWithAAD(encrypted[i], nonces[i], key, []byte(fmt.Sprintf("%s:%d", fileID, i)))
				if e != nil {
					fmt.Println(e)
					return
				}
				if _, e = restored.Write(plain); e != nil {
					fmt.Println(e)
					return
				}
			}
			if err := restored.Close(); err != nil {
				fmt.Println(err)
				return
			}
			gotHash, err := computeFileHash(restoredPath)
			wantHash, hashErr := computeFileHash(path)
			if err != nil || hashErr != nil || gotHash != wantHash {
				fmt.Println("benchmark integrity verification failed")
				return
			}
			restoreT = append(restoreT, time.Since(t).Seconds())
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak {
				peak = ms.HeapAlloc
			}
		}
		fmt.Printf("\nPayload %d MiB (5 trials)\n", sizeMB)
		printRateStats("Disk read + 2 MiB chunking", readT, float64(sizeMB))
		printRateStats("AES-256-GCM encryption", encT, float64(sizeMB))
		printStats("SQLite manifest write", dbT, "ms")
		printRateStats("Restoration + decryption + SHA-256", restoreT, float64(sizeMB))
		fmt.Printf("Peak heap: %.2f MB\n", float64(peak)/(1024*1024))
	}
}

func printStats(label string, values []float64, unit string) {
	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))
	variance := 0.0
	for _, v := range values {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(values))
	fmt.Printf("  %s: %v %s; mean %.3f ± %.3f %s\n", label, values, unit, mean, math.Sqrt(variance), unit)
}
func printRateStats(label string, values []float64, mib float64) {
	rates := make([]float64, len(values))
	for i, v := range values {
		rates[i] = mib / v
	}
	printStats(label, rates, "MiB/s")
}

// startLocalAPIServer launches the HTTP REST API on standard localhost (no mesh).
func startLocalAPIServer(database *db.DB) {
	port := 8080
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		if p, err := strconv.Atoi(portEnv); err == nil {
			port = p
		}
	}

	storageDir := os.Getenv("STORAGE_DIR")
	if storageDir == "" {
		storageDir = storage.DefaultStoragePath()
	}
	masterKey, keySource, err := crypto.LoadMasterKeyForVault(storageDir)
	if err != nil {
		fmt.Printf("ERROR loading master key: %v\n", err)
		return
	}
	fmt.Printf("[CRYPTO] Master key loaded from %s.\n", keySource)

	config := api.ServerConfig{
		Port:       port,
		StorageDir: storageDir,
		MasterKey:  masterKey,
		Node:       nil, // No Tailscale node -- local-only mode
	}

	server := api.NewServer(database, config)

	fmt.Println("\n------------------------------------------------------------------")
	fmt.Println(">>> LAUNCHING AURACLOUD LOCAL REST API SERVER & WEB DASHBOARD")
	fmt.Println("------------------------------------------------------------------")
	fmt.Printf("  Web UI Dashboard: http://localhost:%d\n", port)
	fmt.Println("------------------------------------------------------------------")
	fmt.Println("  REST API Endpoints:")
	fmt.Printf("  - GET  http://localhost:%d/health\n", port)
	fmt.Printf("  - GET  http://localhost:%d/api/v1/files\n", port)
	fmt.Printf("  - POST http://localhost:%d/api/v1/files/upload\n", port)
	fmt.Println("------------------------------------------------------------------")

	if err := server.Start(); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

// startMeshP2PNode initializes an embedded Tailscale WireGuard node and serves the REST API
// on the encrypted private mesh network interface.
func startMeshP2PNode(database *db.DB) {
	fmt.Println("\n------------------------------------------------------------------")
	fmt.Println(">>> LAUNCHING AURACLOUD P2P TAILSCALE MESH NODE")
	fmt.Println("------------------------------------------------------------------")

	// Build node configuration from environment / defaults.
	nodeCfg := network.DefaultNodeConfig()

	// Override config with environment variables if present
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		if p, err := strconv.Atoi(portEnv); err == nil {
			nodeCfg.Port = p
		}
	}
	if hostEnv := os.Getenv("TSNET_HOSTNAME"); hostEnv != "" {
		nodeCfg.Hostname = hostEnv
	}
	if dirEnv := os.Getenv("TSNET_DIR"); dirEnv != "" {
		nodeCfg.StateDir = dirEnv
	}

	storageDir := os.Getenv("STORAGE_DIR")
	if storageDir == "" {
		storageDir = storage.DefaultStoragePath()
	}

	fmt.Printf("  Node Hostname  : %s\n", nodeCfg.Hostname)
	fmt.Printf("  State Directory: %s\n", nodeCfg.StateDir)
	fmt.Printf("  Storage Directory: %s\n", storageDir)
	fmt.Printf("  Auth Key       : %s\n", func() string {
		if nodeCfg.AuthKey != "" {
			return "[SET via TAILSCALE_AUTHKEY env var]"
		}
		return "[NOT SET — browser login URL will be printed]"
	}())
	fmt.Printf("  Mesh Port      : %d\n", nodeCfg.Port)
	fmt.Printf("  Ephemeral      : %v\n", nodeCfg.Ephemeral)
	fmt.Println("------------------------------------------------------------------")

	// Initialize the embedded tsnet node (does NOT connect yet).
	node, err := network.NewNode(nodeCfg)
	if err != nil {
		fmt.Printf("ERROR: Failed to create tsnet node: %v\n", err)
		return
	}
	defer node.Close()

	// Start the WireGuard mesh listener. This triggers the Tailscale authentication flow.
	addr := fmt.Sprintf(":%d", nodeCfg.Port)
	ln, err := node.StartListener("tcp", addr)
	if err != nil {
		fmt.Printf("ERROR: Failed to start tsnet mesh listener: %v\n", err)
		return
	}

	fmt.Printf("\n[MESH] WireGuard node started. Listening on Tailscale mesh interface at port %d.\n", nodeCfg.Port)
	fmt.Println("[MESH] (If no TAILSCALE_AUTHKEY was provided, check for a login URL above.)")
	fmt.Println("[MESH] Other AuraCloud nodes on your Tailscale mesh can now reach this node.")
	fmt.Println("[MESH] Press Ctrl+C to stop the mesh node.")

	masterKey, keySource, err := crypto.LoadMasterKeyForVault(storageDir)
	if err != nil {
		fmt.Printf("ERROR loading master key: %v\n", err)
		return
	}
	fmt.Printf("[CRYPTO] Master key loaded from %s.\n", keySource)

	// Configure the API server WITH the live mesh node reference.
	config := api.ServerConfig{
		Port:       nodeCfg.Port,
		StorageDir: storageDir,
		MasterKey:  masterKey,
		Node:       node, // Live tsnet node — mesh mode enabled
	}

	server := api.NewServer(database, config)
	// Phase 2: recover durable transfers left by offline peers or a prior process.
	// Cancellation happens when mesh serving returns and before the tsnet node closes.
	syncCtx, cancelSync := context.WithCancel(context.Background())
	defer cancelSync()
	server.StartSyncQueueWorker(syncCtx)

	fmt.Println("\n  Endpoints reachable on the Tailscale mesh:")
	fmt.Printf("  - GET    http://%s:%d/health\n", nodeCfg.Hostname, nodeCfg.Port)
	fmt.Printf("  - GET    http://%s:%d/api/v1/files\n", nodeCfg.Hostname, nodeCfg.Port)
	fmt.Printf("  - POST   http://%s:%d/api/v1/files/upload\n", nodeCfg.Hostname, nodeCfg.Port)
	fmt.Printf("  - GET    http://%s:%d/api/v1/files/download/{id}\n", nodeCfg.Hostname, nodeCfg.Port)
	fmt.Printf("  - DELETE http://%s:%d/api/v1/files/delete/{id}\n", nodeCfg.Hostname, nodeCfg.Port)
	fmt.Printf("  - GET    http://%s:%d/api/v1/node/status\n", nodeCfg.Hostname, nodeCfg.Port)
	fmt.Println("------------------------------------------------------------------")

	// 1. Dual Listener Fix: Launch local REST server in background for local UI access
	go func() {
		fmt.Printf("[SYSTEM] Starting local HTTP listener on http://127.0.0.1:%d for local dashboard access...\n", nodeCfg.Port)
		if err := server.Start(); err != nil {
			fmt.Printf("[SYSTEM] Local REST API server error: %v\n", err)
		}
	}()

	// 2. Auto-launch default system browser to local dashboard URL
	go func() {
		time.Sleep(500 * time.Millisecond)
		url := fmt.Sprintf("http://localhost:%d", nodeCfg.Port)
		if err := utils.OpenBrowser(url); err != nil {
			fmt.Printf("[SYSTEM] Could not auto-launch browser: %v. Please open %s manually.\n", err, url)
		} else {
			fmt.Printf("[SYSTEM] Launched default browser to %s\n", url)
		}
	}()

	// 3. Serve HTTP over the WireGuard mesh listener
	if err := server.StartWithListener(ln); err != nil {
		fmt.Printf("Mesh API server exited: %v\n", err)
	}
}

// --- Existing pipeline functions (unchanged from Milestone 3) ---

func runAutomatedVerification(database *db.DB) {
	fmt.Println("\n------------------------------------------------------------------")
	fmt.Println(">>> STARTING AUTOMATED SQLITE MANIFEST PIPELINE VERIFICATION")
	fmt.Println("------------------------------------------------------------------")

	samplePath := "sample_verification.dat"
	sampleSize := int64(5 * 1024 * 1024)

	fmt.Printf("[1/7] Generating %d MB synthetic test file: %s ...\n", sampleSize/(1024*1024), samplePath)
	err := generateSampleFile(samplePath, sampleSize)
	if err != nil {
		fmt.Printf("ERROR creating sample file: %v\n", err)
		return
	}
	defer os.Remove(samplePath)

	origHash, err := computeFileHash(samplePath)
	if err != nil {
		fmt.Printf("ERROR computing original file hash: %v\n", err)
		return
	}
	fmt.Printf("      Original File SHA-256 Digest: %s\n", origHash)

	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		fmt.Printf("ERROR generating AES master key: %v\n", err)
		return
	}
	fmt.Printf("[2/7] Generated 32-byte (256-bit) AES Master Secret Key.\n")

	restoredPath := "restored_sample.dat"
	err = executePipelineWithDB(database, samplePath, restoredPath, masterKey)
	if err != nil {
		fmt.Printf("ERROR in pipeline: %v\n", err)
		return
	}

	fmt.Println("[7/7] Verifying Restored File Integrity against Original SHA-256...")
	restoredHash, err := computeFileHash(restoredPath)
	if err != nil {
		fmt.Printf("ERROR computing restored file hash: %v\n", err)
		return
	}
	fmt.Printf("      Restored File SHA-256 Digest: %s\n", restoredHash)

	if origHash == restoredHash {
		fmt.Println("\n==================================================================")
		fmt.Println(" [SUCCESS] BYTE-FOR-BYTE FIDELITY CONFIRMED VIA SQLITE MANIFEST!")
		fmt.Println(" Restored output created at: ", restoredPath)
		fmt.Println("==================================================================")
	} else {
		fmt.Println("\n==================================================================")
		fmt.Println(" [FAILURE] DATA CORRUPTION DETECTED!")
		fmt.Println("==================================================================")
	}
}

func processCustomFile(database *db.DB, filePath string) {
	info, err := os.Stat(filePath)
	if err != nil {
		fmt.Printf("ERROR: Cannot access file '%s': %v\n", filePath, err)
		return
	}
	fmt.Printf("\nProcessing custom file: %s (%d bytes)\n", filePath, info.Size())

	origHash, err := computeFileHash(filePath)
	if err != nil {
		fmt.Printf("ERROR computing hash: %v\n", err)
		return
	}
	fmt.Printf("Original SHA-256 Digest: %s\n", origHash)

	ext := filepath.Ext(filePath)
	if ext == "" {
		ext = ".restored"
	}
	restoredPath := "restored_sample" + ext
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		fmt.Printf("ERROR generating key: %v\n", err)
		return
	}

	err = executePipelineWithDB(database, filePath, restoredPath, masterKey)
	if err != nil {
		fmt.Printf("ERROR in pipeline: %v\n", err)
		return
	}

	restoredHash, err := computeFileHash(restoredPath)
	if err != nil {
		fmt.Printf("ERROR computing restored hash: %v\n", err)
		return
	}
	fmt.Printf("Restored SHA-256 Digest: %s\n", restoredHash)

	if origHash == restoredHash {
		fmt.Printf("SUCCESS: Restored to '%s' using SQLite Manifest!\n", restoredPath)
	} else {
		fmt.Println("FAILURE: Hash mismatch on custom file restoration!")
	}
}

func executePipelineWithDB(database *db.DB, inputPath string, outputPath string, key []byte) error {
	info, err := os.Stat(inputPath)
	if err != nil {
		return err
	}

	storageDir := storage.DefaultStoragePath()
	if err := storage.EnsureStorageDir(storageDir); err != nil {
		return fmt.Errorf("failed to setup storage dir: %w", err)
	}

	fmt.Println("\n--- [Phase 1: Fixed 2MB Chunking] ---")
	startTime := time.Now()
	chunks, err := chunker.ChunkFile(inputPath, chunker.DefaultChunkSize)
	if err != nil {
		return fmt.Errorf("chunking failed: %w", err)
	}
	fmt.Printf("File sliced into %d chunk(s) in %v.\n", len(chunks), time.Since(startTime))

	fmt.Println("\n--- [Phase 2: Cryptographic CID, AES-256-GCM Encryption & Disk Storage] ---")
	var chunkRecords []db.ChunkRecord
	fileID := uuid.New().String()

	for _, c := range chunks {
		ciphertext, nonce, err := crypto.EncryptChunkWithAAD(c.Data, key, []byte(fmt.Sprintf("%s:%d", fileID, c.Index)))
		if err != nil {
			return fmt.Errorf("failed to encrypt chunk index %d: %w", c.Index, err)
		}
		cid := crypto.GenerateCID(ciphertext)
		err = storage.SaveEncryptedChunk(storageDir, cid, nonce, ciphertext)
		if err != nil {
			return fmt.Errorf("failed to save chunk %s to disk: %w", cid, err)
		}
		nonceHex := hex.EncodeToString(nonce)
		chunkRecords = append(chunkRecords, db.ChunkRecord{
			FileID:     fileID,
			ChunkIndex: c.Index,
			CID:        cid,
			NonceHex:   nonceHex,
			ChunkSize:  c.Size,
		})
		fmt.Printf("  Chunk #%d | Size: %7d bytes | CID: %s | Nonce: %s\n", c.Index, c.Size, cid, nonceHex)
	}

	fmt.Println("\n--- [Phase 3: SQLite Manifest Registration] ---")
	mimeType := detectMimeType(inputPath)
	fileRecord := db.FileRecord{
		ID:          fileID,
		FileName:    filepath.Base(inputPath),
		FileSize:    info.Size(),
		MimeType:    mimeType,
		TotalChunks: len(chunks),
		CreatedAt:   time.Now(),
	}
	err = database.RegisterFile(fileRecord, chunkRecords)
	if err != nil {
		return fmt.Errorf("failed to register file in DB: %w", err)
	}
	fmt.Printf("  [DB] Saved [ID: %s | Name: %s | Chunks: %d]\n", fileID, fileRecord.FileName, fileRecord.TotalChunks)

	fmt.Println("\n--- [Phase 4: SQLite Manifest Retrieval] ---")
	manifest, err := database.GetFileManifest(fileID)
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}
	fmt.Printf("  Loaded %d chunk mapping records from DB.\n", len(manifest.Chunks))

	fmt.Println("\n--- [Phase 5: Manifest-Driven Decryption & Reassembly] ---")
	decryptedChunks := make([][]byte, len(manifest.Chunks))
	for i, chunkRec := range manifest.Chunks {
		nonceFromDisk, ciphertext, err := storage.LoadEncryptedChunk(storageDir, chunkRec.CID)
		if err != nil {
			return fmt.Errorf("failed to load chunk %s: %w", chunkRec.CID, err)
		}
		plainBytes, err := crypto.DecryptChunkCompatible(ciphertext, nonceFromDisk, key, []byte(fmt.Sprintf("%s:%d", chunkRec.FileID, chunkRec.ChunkIndex)))
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk index %d: %w", chunkRec.ChunkIndex, err)
		}
		decryptedChunks[i] = plainBytes
		fmt.Printf("  Decrypted Chunk #%d | Bytes: %d\n", chunkRec.ChunkIndex, len(plainBytes))
	}

	return storage.ReassembleFile(outputPath, decryptedChunks)
}

func listFilesFromDB(database *db.DB) {
	fmt.Println("\n------------------------------------------------------------------")
	fmt.Println(">>> REGISTERED FILES IN SQLITE MANIFEST DATABASE")
	fmt.Println("------------------------------------------------------------------")

	files, err := database.ListFiles()
	if err != nil {
		fmt.Printf("ERROR listing files: %v\n", err)
		return
	}
	if len(files) == 0 {
		fmt.Println("No files registered yet.")
		return
	}

	fmt.Printf("%-38s | %-24s | %-12s | %-16s | %-8s | %s\n",
		"FILE ID", "FILE NAME", "SIZE (BYTES)", "MIME TYPE", "CHUNKS", "CREATED AT")
	fmt.Println(strings.Repeat("-", 120))

	for _, f := range files {
		fmt.Printf("%-38s | %-24s | %-12d | %-16s | %-8d | %s\n",
			f.ID, truncateStr(f.FileName, 24), f.FileSize, f.MimeType, f.TotalChunks, f.CreatedAt.Format("2006-01-02 15:04:05"))
	}
}

func detectMimeType(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return "application/octet-stream"
	}
	defer file.Close()
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	if n == 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(buf[:n])
}

func generateSampleFile(filePath string, size int64) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	buf := make([]byte, 64*1024)
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	var written int64
	for written < size {
		toWrite := int64(len(buf))
		if size-written < toWrite {
			toWrite = size - written
		}
		n, err := file.Write(buf[:toWrite])
		if err != nil {
			return err
		}
		written += int64(n)
	}
	return nil
}

func computeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func truncateStr(str string, maxLen int) string {
	if len(str) <= maxLen {
		return str
	}
	return str[:maxLen-3] + "..."
}
