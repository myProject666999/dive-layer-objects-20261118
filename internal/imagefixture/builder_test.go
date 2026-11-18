package imagefixture

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixturesAreDeterministic(t *testing.T) {
	for name, spec := range Fixtures() {
		var a, b bytes.Buffer
		require.NoError(t, spec.Write(&a), name)
		require.NoError(t, spec.Write(&b), name)
		require.Equal(t, a.Bytes(), b.Bytes(), name)
	}
}

func TestOCISaveDiffIDs(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Fixtures()["oci-save-zstd"].Write(&buf))
	files := map[string][]byte{}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		files[hdr.Name], _ = io.ReadAll(tr)
	}

	var manifest []dockerManifest
	require.NoError(t, json.Unmarshal(files["manifest.json"], &manifest))
	var cfg struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	require.NoError(t, json.Unmarshal(files[manifest[0].Config], &cfg))
	require.Len(t, cfg.RootFS.DiffIDs, len(manifest[0].Layers))

	// diff ids are digests of the uncompressed layer tars
	for i, p := range manifest[0].Layers {
		dec, err := zstd.NewReader(bytes.NewReader(files[p]))
		require.NoError(t, err)
		raw, err := io.ReadAll(dec)
		require.NoError(t, err)
		sum := sha256.Sum256(raw)
		require.Equal(t, cfg.RootFS.DiffIDs[i], "sha256:"+hex.EncodeToString(sum[:]))
	}
}

func TestLayerTar_SparseRoundTrip(t *testing.T) {
	const apparent = 1 << 20 // 1 MiB apparent, only 17 real bytes stored
	entries := []Entry{
		{Name: "var/", Type: tar.TypeDir},
		{
			Name:         "var/big.bin",
			ApparentSize: apparent,
			Sparse: []SparseFragment{
				{Offset: 4096, Content: "hello sparse"}, // 12 bytes
				{Offset: 8192, Content: "five!"},        // 5 bytes
			},
		},
		// a normal member next to the sparse one proves raw blocks interleave with tar.Writer output
		{Name: "var/plain.txt", Content: "plain"},
	}
	raw, err := layerTar(entries)
	require.NoError(t, err)

	tr := tar.NewReader(bytes.NewReader(raw))
	var sawSparse, sawPlain bool
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		switch hdr.Name {
		case "var/big.bin":
			sawSparse = true
			// apparent length is what the reconstructed file reports
			require.Equal(t, int64(apparent), hdr.Size)
			require.Equal(t, "4096,12,8192,5", hdr.PAXRecords["GNU.sparse.map"])
			require.Equal(t, "0", hdr.PAXRecords["GNU.sparse.major"])
			require.Equal(t, "1", hdr.PAXRecords["GNU.sparse.minor"])

			body, err := io.ReadAll(tr)
			require.NoError(t, err)
			require.Len(t, body, apparent, "the logical stream has the apparent length")
			assert.Equal(t, "hello sparse", string(body[4096:4108]))
			assert.Equal(t, "five!", string(body[8192:8197]))
			assert.Equal(t, make([]byte, 100), body[0:100], "unmapped regions read back as zeros")
		case "var/plain.txt":
			sawPlain = true
			body, err := io.ReadAll(tr)
			require.NoError(t, err)
			assert.Equal(t, "plain", string(body))
		}
	}
	require.True(t, sawSparse, "sparse member was read back")
	require.True(t, sawPlain, "ordinary member alongside sparse one was read back")
}

func TestLayerTar_SparseValidation(t *testing.T) {
	tests := []struct {
		name    string
		entry   Entry
		wantErr string
	}{
		{
			name:    "missing apparent size",
			entry:   Entry{Name: "x", Sparse: []SparseFragment{{Offset: 0, Content: "a"}}},
			wantErr: "ApparentSize",
		},
		{
			name: "fragment past apparent size",
			entry: Entry{
				Name: "x", ApparentSize: 4,
				Sparse: []SparseFragment{{Offset: 0, Content: "too long"}},
			},
			wantErr: "past the apparent size",
		},
		{
			name: "fragments out of order",
			entry: Entry{
				Name: "x", ApparentSize: 100,
				Sparse: []SparseFragment{{Offset: 10, Content: "b"}, {Offset: 5, Content: "a"}},
			},
			wantErr: "ascending",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := layerTar([]Entry{tt.entry})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLayerTar_SparseDeterministic(t *testing.T) {
	entries := []Entry{{
		Name:         "big.bin",
		ApparentSize: 4096,
		Sparse:       []SparseFragment{{Offset: 100, Content: "data"}},
	}}
	a, err := layerTar(entries)
	require.NoError(t, err)
	b, err := layerTar(entries)
	require.NoError(t, err)
	assert.Equal(t, a, b)
}
