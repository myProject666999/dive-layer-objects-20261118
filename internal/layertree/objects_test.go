package layertree

import (
	"archive/tar"
	"fmt"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wagoodman/dive/internal/imagefixture"
)

func TestAllocatedSize(t *testing.T) {
	const big = 1 << 20
	tests := []struct {
		name string
		hdr  tar.Header
		want int64
	}{
		{name: "plain regular", hdr: tar.Header{Typeflag: tar.TypeReg, Size: 100}, want: 100},
		{name: "v7 regular", hdr: tar.Header{Typeflag: tar.TypeRegA, Size: 7}, want: 7},
		{name: "empty regular", hdr: tar.Header{Typeflag: tar.TypeReg, Size: 0}, want: 0},
		{
			name: "sparse one fragment",
			hdr: tar.Header{
				Typeflag:   tar.TypeReg,
				Size:       big,
				PAXRecords: map[string]string{"GNU.sparse.map": "4096,12"},
			},
			want: 12,
		},
		{
			name: "sparse two fragments",
			hdr: tar.Header{
				Typeflag:   tar.TypeReg,
				Size:       big,
				PAXRecords: map[string]string{"GNU.sparse.map": "0,10,100,5"},
			},
			want: 15,
		},
		{
			name: "empty map falls back to apparent",
			hdr: tar.Header{
				Typeflag:   tar.TypeReg,
				Size:       big,
				PAXRecords: map[string]string{"GNU.sparse.map": ""},
			},
			want: big,
		},
		{
			// GNU 1.0 keeps its map out of PAXRecords, so the apparent size is all the header offers
			name: "sparse 1.0 falls back to apparent",
			hdr: tar.Header{
				Typeflag:   tar.TypeGNUSparse,
				Size:       big,
				PAXRecords: map[string]string{"GNU.sparse.major": "1", "GNU.sparse.minor": "0"},
			},
			want: big,
		},
		{
			name: "malformed odd pair count",
			hdr: tar.Header{
				Typeflag:   tar.TypeReg,
				Size:       big,
				PAXRecords: map[string]string{"GNU.sparse.map": "0,10,5"},
			},
			want: big,
		},
		{
			name: "malformed non numeric",
			hdr: tar.Header{
				Typeflag:   tar.TypeReg,
				Size:       big,
				PAXRecords: map[string]string{"GNU.sparse.map": "0,x"},
			},
			want: big,
		},
		{
			name: "malformed negative",
			hdr: tar.Header{
				Typeflag:   tar.TypeReg,
				Size:       big,
				PAXRecords: map[string]string{"GNU.sparse.map": "0,-1"},
			},
			want: big,
		},
		{name: "hardlink is zero", hdr: tar.Header{Typeflag: tar.TypeLink, Size: 0, Linkname: "a"}, want: 0},
		{name: "hardlink never counts named size", hdr: tar.Header{Typeflag: tar.TypeLink, Size: 500, Linkname: "a"}, want: 0},
		{name: "symlink is zero", hdr: tar.Header{Typeflag: tar.TypeSymlink, Size: 4}, want: 0},
		{name: "dir is zero", hdr: tar.Header{Typeflag: tar.TypeDir, Size: 0}, want: 0},
		{name: "char device is zero", hdr: tar.Header{Typeflag: tar.TypeChar}, want: 0},
		{name: "block device is zero", hdr: tar.Header{Typeflag: tar.TypeBlock}, want: 0},
		{name: "fifo is zero", hdr: tar.Header{Typeflag: tar.TypeFifo}, want: 0},
		{name: "nil header is zero", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, AllocatedSize(&tt.hdr))
		})
	}
}

func TestIsSparse(t *testing.T) {
	assert.False(t, IsSparse(nil))
	assert.False(t, IsSparse(&tar.Header{Typeflag: tar.TypeReg, Size: 10}))
	assert.True(t, IsSparse(&tar.Header{
		Typeflag:   tar.TypeReg,
		Size:       1 << 20,
		PAXRecords: map[string]string{"GNU.sparse.map": "0,10"},
	}))
	// malformed map is not a usable sparse map
	assert.False(t, IsSparse(&tar.Header{
		Typeflag:   tar.TypeReg,
		Size:       1 << 20,
		PAXRecords: map[string]string{"GNU.sparse.map": "0"},
	}))
}

// nodeAt pairs a catalog reference with the layer index it belongs to.
type nodeAt struct {
	layer int
	ref   *file.Reference
}

func collectRefs(t *testing.T, img *image.Image) map[string]nodeAt {
	t.Helper()
	refs := make(map[string]nodeAt)
	for layer := range img.Layers {
		require.NoError(t, Walk(img.Layers[layer].Tree, nil, func(n *filenode.FileNode, _ bool) error {
			refs[nodeKey(layer, string(n.RealPath))] = nodeAt{layer: layer, ref: n.Reference}
			return nil
		}))
	}
	return refs
}

func nodeKey(layer int, path string) string { return fmt.Sprintf("%d:%s", layer, path) }

func TestResolveIdentity(t *testing.T) {
	img := imagefixture.Load(t, "hardlink-and-symlink")
	refs := collectRefs(t, img)

	tool := refs[nodeKey(0, "/usr/bin/tool")]
	toolHard := refs[nodeKey(0, "/usr/bin/tool-hard")]
	require.NotNil(t, tool.ref)
	require.NotNil(t, toolHard.ref)

	// a regular file resolves to its own identity and carries bytes
	own, ok := ResolveIdentity(img, img.Layers[tool.layer].Tree, tool.ref)
	require.True(t, ok)

	// the same-layer hardlink resolves to the regular member's identity, not its own
	linkID, ok := ResolveIdentity(img, img.Layers[toolHard.layer].Tree, toolHard.ref)
	require.True(t, ok)
	assert.Equal(t, own.ID(), linkID.ID())

	// a hardlink naming a file only present in a lower layer cannot be adopted here: it carries no
	// data of its own, so it has no identity in this layer's accounting
	libxHard := refs[nodeKey(1, "/usr/bin/libx-hard")]
	require.NotNil(t, libxHard.ref)
	_, ok = ResolveIdentity(img, img.Layers[libxHard.layer].Tree, libxHard.ref)
	assert.False(t, ok)

	// nil guards
	_, ok = ResolveIdentity(img, img.Layers[0].Tree, nil)
	assert.False(t, ok)
	_, ok = ResolveIdentity(nil, img.Layers[0].Tree, tool.ref)
	assert.False(t, ok)
}

func TestResolveIdentityChainsAndCycles(t *testing.T) {
	img := imagefixture.LoadSpec(t, imagefixture.Spec{
		Format: imagefixture.OCISave,
		Layers: [][]imagefixture.Entry{{
			{Name: "d/", Type: tar.TypeDir},
			{Name: "d/reg", Content: "0123456789"},
			// a chain of hardlinks ending at the regular member
			{Name: "d/link1", Type: tar.TypeLink, Linkname: "d/reg"},
			{Name: "d/link2", Type: tar.TypeLink, Linkname: "d/link1"},
			// a self-referential cycle with no regular target
			{Name: "d/cycle", Type: tar.TypeLink, Linkname: "d/cycle"},
			// a dangling link
			{Name: "d/dangle", Type: tar.TypeLink, Linkname: "d/missing"},
		}},
	})

	refs := collectRefs(t, img)
	tree := img.Layers[0].Tree
	reg := refs[nodeKey(0, "/d/reg")]

	regID, ok := ResolveIdentity(img, tree, reg.ref)
	require.True(t, ok)

	for _, p := range []string{"/d/link1", "/d/link2"} {
		id, ok := ResolveIdentity(img, tree, refs[nodeKey(0, p)].ref)
		require.True(t, ok, p)
		assert.Equal(t, regID.ID(), id.ID(), p)
	}

	for _, p := range []string{"/d/cycle", "/d/dangle"} {
		_, ok := ResolveIdentity(img, tree, refs[nodeKey(0, p)].ref)
		assert.False(t, ok, p)
	}
}
