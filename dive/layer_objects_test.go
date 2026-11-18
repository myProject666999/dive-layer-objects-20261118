package dive

import (
	"archive/tar"
	"context"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wagoodman/dive/internal/imagefixture"
	"github.com/wagoodman/dive/internal/layertree"
)

func analyzeSpec(t *testing.T, layers ...[]imagefixture.Entry) *Analysis {
	t.Helper()
	img := imagefixture.LoadSpec(t, imagefixture.Spec{Format: imagefixture.OCISave, Layers: layers})
	a, err := Analyze(context.Background(), "spec", img)
	require.NoError(t, err)
	return a
}

func ineffMap(a *Analysis) map[string]Inefficiency {
	out := make(map[string]Inefficiency, len(a.Inefficiencies))
	for _, in := range a.Inefficiencies {
		out[in.Path] = in
	}
	return out
}

func layerSizes(a *Analysis) []uint64 {
	out := make([]uint64, len(a.Layers))
	for i, l := range a.Layers {
		out[i] = l.Size
	}
	return out
}

// sparseEntry builds one sparse Entry with a single 12-byte fragment and a 1 MiB apparent size.
func sparseEntry(name string) imagefixture.Entry {
	return imagefixture.Entry{
		Name:         name,
		ApparentSize: 1 << 20,
		Sparse:       []imagefixture.SparseFragment{{Offset: 4096, Content: strings.Repeat("s", 12)}},
	}
}

// headerAtPath returns the tar header the catalog stores for the given final-tree path.
func headerAtPath(t *testing.T, img *image.Image, p string) *tar.Header {
	t.Helper()
	var hdr *tar.Header
	require.NoError(t, layertree.Walk(img.SquashedTree(), nil, func(n *filenode.FileNode, _ bool) error {
		if string(n.RealPath) == p && n.Reference != nil {
			if h, ok := layertree.Header(img, n.Reference); ok {
				hdr = h
			}
		}
		return nil
	}))
	require.NotNil(t, hdr, "no header found at %s", p)
	return hdr
}

func TestAnalyze_SparseWasteUsesAllocatedBytes(t *testing.T) {
	// overwritten sparse file: 12 allocated bytes wasted, never the 1 MiB apparent length
	a, err := Analyze(context.Background(), "sparse-file-waste", imagefixture.Load(t, "sparse-file-waste"))
	require.NoError(t, err)

	assert.Equal(t, uint64(12), a.WastedBytes)
	assert.InDelta(t, 100.0/112.0, a.Efficiency, 1e-12)
	ineff := ineffMap(a)["/var/big.bin"]
	assert.Equal(t, uint64(12), ineff.SizeBytes)
	assert.Equal(t, 2, ineff.Count)

	// the layer size reflects allocated storage, not apparent length
	assert.Equal(t, []uint64{12, 100}, layerSizes(a))
	assert.Equal(t, uint64(112), a.SizeBytes)

	// the surviving file is the layer-2 plain copy; the sparse header it replaced lives in layer 0
	finalHdr := headerAtPath(t, a.Image, "/var/big.bin")
	assert.Equal(t, int64(100), finalHdr.Size)
	assert.False(t, layertree.IsSparse(finalHdr))

	sparseHdr := headerInLayer(t, a.Image, 0, "/var/big.bin")
	assert.Equal(t, int64(1<<20), sparseHdr.Size)
	assert.Equal(t, int64(12), layertree.AllocatedSize(sparseHdr))
	assert.True(t, layertree.IsSparse(sparseHdr))
}

// headerInLayer returns the tar header for a path in one layer's own diff tree.
func headerInLayer(t *testing.T, img *image.Image, layer int, p string) *tar.Header {
	t.Helper()
	var hdr *tar.Header
	require.NoError(t, layertree.Walk(img.Layers[layer].Tree, nil, func(n *filenode.FileNode, _ bool) error {
		if string(n.RealPath) == p && n.Reference != nil {
			if h, ok := layertree.Header(img, n.Reference); ok {
				hdr = h
			}
		}
		return nil
	}))
	require.NotNil(t, hdr, "no header found at %s in layer %d", p, layer)
	return hdr
}

func TestAnalyze_SparseRemovedWastesAllocatedBytes(t *testing.T) {
	a, err := Analyze(context.Background(), "sparse-file-removed", imagefixture.Load(t, "sparse-file-removed"))
	require.NoError(t, err)

	assert.Equal(t, uint64(12), a.WastedBytes)
	assert.Equal(t, 0.0, a.Efficiency)
	assert.Equal(t, uint64(12), a.SizeBytes)
	assert.Equal(t, uint64(12), ineffMap(a)["/var/big.bin"].SizeBytes)
}

func TestAnalyze_SparseOverwrittenBySparse(t *testing.T) {
	// both copies sparse: only the 12 allocated bytes of the lower one are wasted, not either apparent size
	layers := [][]imagefixture.Entry{
		{sparseEntry("var/big.bin")},
		{{
			Name:         "var/big.bin",
			ApparentSize: 1 << 20,
			Sparse:       []imagefixture.SparseFragment{{Offset: 0, Content: strings.Repeat("t", 20)}},
		}},
	}
	a := analyzeSpec(t, layers...)
	assert.Equal(t, uint64(12), a.WastedBytes)
	assert.InDelta(t, 20.0/32.0, a.Efficiency, 1e-12)
}

func TestAnalyze_HardlinkThreeNamesCountedOnce(t *testing.T) {
	a, err := Analyze(context.Background(), "hardlink-three-names", imagefixture.Load(t, "hardlink-three-names"))
	require.NoError(t, err)

	assert.Empty(t, a.Inefficiencies)
	assert.Equal(t, 1.0, a.Efficiency)
	assert.Equal(t, uint64(0), a.WastedBytes)
	// one 400-byte data section, not three, and the layer reports 400 not 1200
	assert.Equal(t, []uint64{400}, layerSizes(a))
	assert.Equal(t, uint64(400), a.SizeBytes)
}

func TestAnalyze_WhiteoutOneHardlinkNameKeepsDataLive(t *testing.T) {
	base := []imagefixture.Entry{
		{Name: "data/", Type: tar.TypeDir},
		{Name: "data/a.txt", Content: strings.Repeat("a", 500)},
		{Name: "data/z.txt", Type: tar.TypeLink, Linkname: "data/a.txt"},
	}
	tests := []struct {
		name  string
		upper []imagefixture.Entry
	}{
		{
			name:  "whiteout the data-carrying name",
			upper: []imagefixture.Entry{{Name: "data/", Type: tar.TypeDir}, {Name: "data/.wh.a.txt"}},
		},
		{
			name:  "whiteout the hardlink name",
			upper: []imagefixture.Entry{{Name: "data/", Type: tar.TypeDir}, {Name: "data/.wh.z.txt"}},
		},
		{
			// c9/c11 shape: a new regular file at one name is a new identity, but the original inode
			// stays reachable through the other name, so nothing is wasted
			name: "overwrite data-carrying name with a regular file",
			upper: []imagefixture.Entry{
				{Name: "data/", Type: tar.TypeDir},
				{Name: "data/a.txt", Content: strings.Repeat("q", 300)},
			},
		},
		{
			name: "overwrite the hardlink name with a regular file",
			upper: []imagefixture.Entry{
				{Name: "data/", Type: tar.TypeDir},
				{Name: "data/z.txt", Content: strings.Repeat("q", 200)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := analyzeSpec(t, base, tt.upper)
			assert.Empty(t, a.Inefficiencies, "the surviving hardlink name keeps the data live")
			assert.Equal(t, 1.0, a.Efficiency)
			assert.Equal(t, uint64(0), a.WastedBytes)
		})
	}
}

func TestAnalyze_CrossLayerAndDanglingHardlinkDegrade(t *testing.T) {
	a, err := Analyze(context.Background(), "cross-layer-and-dangling", imagefixture.Load(t, "cross-layer-and-dangling-hardlink"))
	require.NoError(t, err)

	// neither malformed hardlink carries data, so nothing is wasted and analysis does not error
	assert.Empty(t, a.Inefficiencies)
	assert.Equal(t, 1.0, a.Efficiency)
	assert.Equal(t, uint64(0), a.WastedBytes)
	assert.Equal(t, []uint64{300, 0}, layerSizes(a))

	// both hardlinks stay zero-size TypeLink entries in the final tree
	for _, p := range []file.Path{"/app/h", "/app/d"} {
		var hdr *tar.Header
		require.NoError(t, layertree.Walk(a.Image.SquashedTree(), nil, func(n *filenode.FileNode, _ bool) error {
			if n.RealPath == p && n.Reference != nil {
				if h, ok := layertree.Header(a.Image, n.Reference); ok {
					hdr = h
				}
			}
			return nil
		}))
		require.NotNil(t, hdr, string(p))
		assert.Equal(t, byte(tar.TypeLink), hdr.Typeflag)
		assert.Zero(t, hdr.Size)
		assert.Zero(t, layertree.AllocatedSize(hdr))
	}
}

func TestAnalyze_HardlinkToSymlinkCarriesNoBytes(t *testing.T) {
	layers := [][]imagefixture.Entry{{
		{Name: "d/", Type: tar.TypeDir},
		{Name: "d/real.txt", Content: "REAL"},
		// a symlink first, then a hardlink naming the symlink: adoption makes the hardlink a symlink,
		// which carries no data of its own
		{Name: "d/sym", Type: tar.TypeSymlink, Linkname: "real.txt"},
		{Name: "d/hard-to-sym", Type: tar.TypeLink, Linkname: "d/sym"},
	}}
	a := analyzeSpec(t, layers...)
	assert.Empty(t, a.Inefficiencies)
	assert.Equal(t, 1.0, a.Efficiency)
	assert.Equal(t, uint64(4), a.SizeBytes, "only the regular file's data is stored")
}

func TestAnalyze_WhiteoutAndNewFileOrderIndependent(t *testing.T) {
	mkLayer := func(whiteoutFirst bool) []imagefixture.Entry {
		wh := imagefixture.Entry{Name: "data/.wh.x"}
		add := imagefixture.Entry{Name: "data/x", Content: strings.Repeat("x", 200)}
		upper := []imagefixture.Entry{{Name: "data/", Type: tar.TypeDir}}
		if whiteoutFirst {
			return append(upper, wh, add)
		}
		return append(upper, add, wh)
	}
	base := []imagefixture.Entry{
		{Name: "data/", Type: tar.TypeDir},
		{Name: "data/x", Content: strings.Repeat("o", 100)},
	}

	first := analyzeSpec(t, base, mkLayer(true))
	second := analyzeSpec(t, base, mkLayer(false))

	// the relative order of a whiteout and the replacement file in one layer must not change a thing
	assert.Equal(t, first.Efficiency, second.Efficiency)
	assert.Equal(t, first.WastedBytes, second.WastedBytes)
	assert.Equal(t, first.Inefficiencies, second.Inefficiencies)
	assert.Equal(t, 100, int(first.WastedBytes), "the lower 100-byte copy is what is wasted")
}

func TestAnalyze_OpaqueDirIdentityNumbersMatchPathModel(t *testing.T) {
	// cross-check the identity-based model against the established path-based numbers for opaque dirs
	a, err := Analyze(context.Background(), "opaque-whiteout-dir", imagefixture.Load(t, "opaque-whiteout-dir"))
	require.NoError(t, err)

	assert.Equal(t, uint64(600), a.WastedBytes)
	assert.InDelta(t, 55.0/655.0, a.Efficiency, 1e-12)
	assert.Equal(t, []uint64{605, 50}, layerSizes(a))
}
