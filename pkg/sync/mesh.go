package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"auracloud/pkg/db"
	"auracloud/pkg/network"
	"auracloud/pkg/storage"
)

// Manifest is the mesh transfer representation. Flat fields support dashboard
// and protocol clients, while File/Chunks preserve all SQLite metadata needed
// to reconstruct a compatible local manifest.
type Manifest struct {
	FileID       string           `json:"file_id"`
	Filename     string           `json:"filename"`
	Size         int64            `json:"size"`
	OriginNode   string           `json:"origin_node"`
	OriginPeerID string           `json:"origin_peer_id"`
	ChunkCIDs    []string         `json:"chunk_cids"`
	File         db.FileRecord    `json:"file"`
	Chunks       []db.ChunkRecord `json:"chunks"`
}

type Result struct {
	PeersQueried    int `json:"peers_queried"`
	FilesDiscovered int `json:"files_discovered"`
	FilesAdded      int `json:"files_added"`
	ChunksFetched   int `json:"chunks_fetched"`
}

type Manager struct {
	Database   *db.DB
	Node       *network.Node
	StorageDir string
	Port       int
}

type remoteFile struct {
	file   db.FileRecord
	chunks []db.ChunkRecord
	peer   string
}
type chunkSource struct {
	peers     []string
	nonceHex  string
	chunkSize int64
}

func (m *Manager) Sync(ctx context.Context) (Result, error) {
	var result Result
	if m == nil || m.Database == nil || m.Node == nil {
		return result, fmt.Errorf("mesh sync is unavailable")
	}
	client := m.Node.Client()
	if client == nil {
		return result, fmt.Errorf("tsnet HTTP client is unavailable")
	}
	peers, err := m.Node.GetOnlinePeerIPs(ctx)
	if err != nil {
		return result, err
	}
	remoteFiles := make([]remoteFile, 0)
	sources := make(map[string]chunkSource)
	var failures []string
	for _, peer := range peers {
		manifests, err := m.fetchManifest(ctx, client, peer)
		if err != nil {
			failures = append(failures, fmt.Sprintf("manifest from %s: %v", peer, err))
			continue
		}
		result.PeersQueried++
		for _, remote := range manifests {
			file := remote.File
			if file.ID == "" {
				file.ID = remote.FileID
			}
			if file.FileName == "" {
				file.FileName = remote.Filename
			}
			if file.FileSize == 0 {
				file.FileSize = remote.Size
			}
			if file.OriginNode == "" {
				file.OriginNode = remote.OriginNode
			}
			if file.OriginPeerID == "" {
				file.OriginPeerID = remote.OriginPeerID
			}
			if file.ID == "" {
				continue
			}
			if file.OriginNode == "" {
				file.OriginNode = "peer-" + peer
			}
			if file.OriginPeerID == "" {
				file.OriginPeerID = peer
			}
			chunks := remote.Chunks
			if len(chunks) == 0 && len(remote.ChunkCIDs) > 0 {
				continue
			} // old/incomplete metadata cannot be safely registered
			valid := true
			for i := range chunks {
				chunk := &chunks[i]
				chunk.FileID = file.ID
				cidBytes, cidErr := hex.DecodeString(chunk.CID)
				nonceBytes, nonceErr := hex.DecodeString(chunk.NonceHex)
				if cidErr != nil || len(cidBytes) != 32 || nonceErr != nil || len(nonceBytes) != storage.StandardNonceSize || chunk.ChunkSize < 0 {
					valid = false
					break
				}
				src := sources[chunk.CID]
				if src.nonceHex != "" && (src.nonceHex != chunk.NonceHex || src.chunkSize != chunk.ChunkSize) {
					valid = false
					break
				}
				src.peers = appendUnique(src.peers, peer)
				src.nonceHex = chunk.NonceHex
				src.chunkSize = chunk.ChunkSize
				sources[chunk.CID] = src
			}
			if !valid {
				failures = append(failures, "invalid or inconsistent chunk metadata in manifest "+file.ID)
				continue
			}
			remoteFiles = append(remoteFiles, remoteFile{file: file, chunks: chunks, peer: peer})
		}
	}
	result.FilesDiscovered = len(remoteFiles)
	missing := make(map[string]chunkSource)
	for cid, source := range sources {
		exists, err := m.Database.HasChunkCID(cid)
		if err != nil {
			return result, err
		}
		if !exists || !storage.ChunkExists(m.StorageDir, cid) {
			missing[cid] = source
		}
	}
	var fetched atomicCounter
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	var errorsMu sync.Mutex
	for cid, source := range missing {
		cid, source := cid, source
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			var err error
			for _, peer := range source.peers {
				if err = m.fetchChunk(ctx, client, peer, cid, source.nonceHex, source.chunkSize); err == nil {
					fetched.Add(1)
					return
				}
			}
			errorsMu.Lock()
			failures = append(failures, fmt.Sprintf("%s: %v", cid, err))
			errorsMu.Unlock()
		}()
	}
	wg.Wait()
	result.ChunksFetched = fetched.Load()
	for _, remote := range remoteFiles {
		complete := true
		for _, chunk := range remote.chunks {
			if !storage.ChunkExists(m.StorageDir, chunk.CID) {
				complete = false
				break
			}
		}
		if !complete {
			continue
		}
		inserted, err := m.Database.RegisterReplicatedManifest(remote.file, remote.chunks)
		if err != nil {
			errorsMu.Lock()
			failures = append(failures, err.Error())
			errorsMu.Unlock()
			continue
		}
		if inserted {
			result.FilesAdded++
		}
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if len(failures) > 0 {
		return result, fmt.Errorf("mesh sync had %d incomplete transfer(s): %s", len(failures), strings.Join(failures, "; "))
	}
	return result, nil
}

func (m *Manager) fetchManifest(parent context.Context, client *http.Client, peer string) ([]Manifest, error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	addr := net.JoinHostPort(peer, strconv.Itoa(m.Port))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/v1/mesh/manifest", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer %s returned %s", peer, resp.Status)
	}
	var manifests []Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&manifests); err != nil {
		return nil, err
	}
	return manifests, nil
}

func (m *Manager) fetchChunk(parent context.Context, client *http.Client, peer, cid, expectedNonce string, chunkSize int64) error {
	if len(cid) != 64 {
		return fmt.Errorf("invalid CID")
	}
	if _, err := hex.DecodeString(cid); err != nil {
		return fmt.Errorf("invalid CID")
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	addr := net.JoinHostPort(peer, strconv.Itoa(m.Port))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/v1/mesh/chunks/"+url.PathEscape(cid), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer %s returned %s", peer, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+4096))
	if err != nil {
		return err
	}
	if len(data) < storage.StandardNonceSize+16 {
		return fmt.Errorf("encrypted chunk is truncated")
	}
	if hex.EncodeToString(data[:storage.StandardNonceSize]) != strings.ToLower(expectedNonce) {
		return fmt.Errorf("nonce does not match manifest metadata")
	}
	if int64(len(data)-storage.StandardNonceSize-16) != chunkSize {
		return fmt.Errorf("chunk size does not match manifest metadata")
	}
	ciphertext := data[storage.StandardNonceSize:]
	digest := sha256.Sum256(ciphertext)
	if hex.EncodeToString(digest[:]) != strings.ToLower(cid) {
		return fmt.Errorf("ciphertext CID verification failed")
	}
	return storage.SaveEncryptedChunkRaw(m.StorageDir, strings.ToLower(cid), data)
}

func appendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}

type atomicCounter struct {
	mu    sync.Mutex
	value int
}

func (c *atomicCounter) Add(v int) { c.mu.Lock(); c.value += v; c.mu.Unlock() }
func (c *atomicCounter) Load() int { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
