package layertree

import (
	"archive/tar"
	"path"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
)

// DataIdentity names one tar data section, independent of the paths that point at it. A regular file
// is its own identity; every same-layer hardlink to it resolves to the same identity as the member
// carrying the bytes. Splitting identity from path is what keeps overwriting or deleting one name of
// a hardlinked inode from charging the still-live data as waste.
type DataIdentity struct {
	id file.ID
}

// ID exposes the underlying catalog id, used as a map key.
func (d DataIdentity) ID() file.ID { return d.id }

// ResolveIdentity returns the data identity of the catalog entry at ref. layerTree must be the
// owning layer's own diff tree, since a hardlink's link name binds to an earlier member of that same
// archive (matching stereoscope's adoption boundary).
//
// ok is false for an entry that carries no allocated bytes: header-only links and dirs, or a
// hardlink stereoscope could not adopt because its target is absent from this layer, is a dir, is
// itself an un-adopted hardlink, or the names form a cycle. Such an entry stays visible in the tree
// and the export at size 0; it simply cannot contribute bytes to waste accounting.
func ResolveIdentity(img *image.Image, layerTree filetree.Reader, ref *file.Reference) (DataIdentity, bool) {
	if img == nil || layerTree == nil || ref == nil {
		return DataIdentity{}, false
	}
	return resolveIdentity(img, layerTree, ref, make(map[file.ID]bool))
}

func resolveIdentity(img *image.Image, layerTree filetree.Reader, ref *file.Reference, visited map[file.ID]bool) (DataIdentity, bool) {
	if ref == nil || visited[ref.ID()] {
		// nil ref, or a hardlink cycle: nothing safe to adopt
		return DataIdentity{}, false
	}

	hdr, ok := Header(img, ref)
	if !ok {
		// an implicit parent dir or an entry without a catalog record has no data section
		return DataIdentity{}, false
	}

	if hdr.Typeflag != tar.TypeLink {
		if AllocatedSize(hdr) <= 0 {
			return DataIdentity{}, false
		}
		return DataIdentity{id: ref.ID()}, true
	}

	// A hardlink names a member of this same archive, relative to the archive root. Look it up in the
	// layer's own tree without link following, the same boundary stereoscope's adoption uses.
	target := file.Path(path.Clean(file.DirSeparator + hdr.Linkname))
	exists, resolution, err := layerTree.File(target)
	if err != nil || !exists || resolution == nil || resolution.Reference == nil {
		// cross-layer, dangling, dir or conflicting hardlink: stereoscope already degraded it to a
		// zero-size entry, and it carries no data of its own
		return DataIdentity{}, false
	}

	visited[ref.ID()] = true
	return resolveIdentity(img, layerTree, resolution.Reference, visited)
}
