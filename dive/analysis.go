package dive

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/tree/node"

	"github.com/wagoodman/dive/internal/layertree"
)

// Analysis is the result of analyzing an image: the stereoscope image itself plus layer and efficiency stats.
//
// The image is borrowed, not owned: it is the caller's image, and anything that reads file contents through it
// (Image.FileCatalog, Image.OpenReference) only works until the caller runs Image.Cleanup().
type Analysis struct {
	// Ref is a label for the image, as passed to Analyze
	Ref   string
	Image *image.Image
	// Layers is in build order, Layers[i] describes Image.Layers[i]
	Layers []Layer
	// Efficiency is 1.0 for an image without duplicated or removed files, lower otherwise
	Efficiency float64
	// SizeBytes is the sum of all layer sizes
	SizeBytes uint64
	// UserSizeBytes is the sum of all layer sizes except the first (base) layer
	UserSizeBytes uint64
	// WastedBytes is the sum of Inefficiencies sizes
	WastedBytes uint64
	// WastedUserPercent is WastedBytes / UserSizeBytes, 0 when there are no user bytes
	WastedUserPercent float64
	// Inefficiencies is sorted by size, largest first, ties by path
	Inefficiencies []Inefficiency
}

// Layer is the per layer info of an Analysis.
type Layer struct {
	Index int
	// Digest is the layer diff ID
	Digest string
	// Command is the history entry that created the layer, "(missing)" when the image has no history for it
	Command string
	Size    uint64
}

// Inefficiency is a path that wastes bytes because a later layer overwrote or removed it.
type Inefficiency struct {
	Path string
	// Count is how many layers the path shows up in (added or removed)
	Count int
	// SizeBytes is the bytes wasted on the path: every copy layers added minus the copy left in the final image
	SizeBytes uint64
}

// Analyze derives layer info and efficiency stats from an already read stereoscope image. ref only labels the result.
func Analyze(ctx context.Context, ref string, img *image.Image) (*Analysis, error) {
	if img == nil {
		return nil, fmt.Errorf("no image to analyze")
	}

	layers := layerInfo(img)
	efficiency, inefficiencies, err := imageEfficiency(ctx, img)
	if err != nil {
		return nil, err
	}

	var sizeBytes, userSizeBytes, wastedBytes uint64
	for i, l := range layers {
		sizeBytes += l.Size
		if i != 0 {
			userSizeBytes += l.Size
		}
	}
	for _, ineff := range inefficiencies {
		wastedBytes += ineff.SizeBytes
	}

	var wastedUserPercent float64
	if userSizeBytes != 0 {
		wastedUserPercent = float64(wastedBytes) / float64(userSizeBytes)
	}

	return &Analysis{
		Ref:               ref,
		Image:             img,
		Layers:            layers,
		Efficiency:        efficiency,
		SizeBytes:         sizeBytes,
		UserSizeBytes:     userSizeBytes,
		WastedBytes:       wastedBytes,
		WastedUserPercent: wastedUserPercent,
		Inefficiencies:    inefficiencies,
	}, nil
}

// layerInfo pairs layers with history entries. History is in build order and has entries for metadata only
// instructions (empty_layer), which own no layer and are skipped. History is optional, so a layer without an
// entry gets "(missing)".
func layerInfo(img *image.Image) []Layer {
	history := img.Metadata.Config.History
	layers := make([]Layer, len(img.Layers))
	histIdx := 0
	for idx, l := range img.Layers {
		createdBy := "(missing)"
		for histIdx < len(history) && history[histIdx].EmptyLayer {
			histIdx++
		}
		if histIdx < len(history) {
			createdBy = history[histIdx].CreatedBy
			histIdx++
		}
		layers[idx] = Layer{
			Index:   int(l.Metadata.Index),
			Digest:  l.Metadata.Digest,
			Command: strings.TrimPrefix(createdBy, "/bin/sh -c "),
			Size:    allocatedLayerSize(img, l),
		}
	}
	return layers
}

// allocatedLayerSize is the storage the layer really occupies: the sum of the tar data sections its
// members carry. A hardlink header carries no data, and a sparse member carries only its mapped
// fragments, so both count their real bytes rather than a named or apparent size. It walks the
// layer's own diff tree once and sums each catalog entry's allocated size. stereoscope's
// Metadata.Size sums raw header sizes and so overstates a sparse layer by its apparent length; it
// stays the fallback when a member has no readable header.
func allocatedLayerSize(img *image.Image, l *image.Layer) uint64 {
	var total int64
	_ = layertree.Walk(l.Tree, nil, func(n *filenode.FileNode, _ bool) error {
		if n.Reference == nil {
			return nil
		}
		if hdr, ok := layertree.Header(img, n.Reference); ok {
			total += layertree.AllocatedSize(hdr)
		}
		return nil
	})
	if total > 0 {
		return uint64(total)
	}
	// no measurable data section (an empty layer, or a tree without catalog headers): keep the
	// metadata value rather than reporting zero for a layer that genuinely holds something
	return uint64(l.Metadata.Size)
}

// identityAccount is one tar data section: the bytes a single member physically carries, plus the path that
// member is reached at for reporting. Every same-layer hardlink resolves to the same account rather than its own.
type identityAccount struct {
	bytes   int64
	carrier file.Path
}

// imageEfficiency scores the image and lists the paths that waste bytes.
//
// It runs two independent passes, because path occurrences and data identities answer different questions:
//
//   - The count pass works per path. A whiteout, an opaque dir or a non-dir put in place of a dir can hide
//     lower paths; those removals are only visible as transitions between one layer's squashed tree and the
//     next, since every squashed tree has whiteout markers stripped. removedPaths finds them. This preserves
//     the "how many layers added or removed the path" count.
//   - The byte pass works per data identity (a catalog id, with same-layer hardlinks resolving to the member
//     they name). A hardlink's extra names carry no data section, so the bytes are counted once no matter how
//     many names point at them. An identity is wasted only when NO name for it survives in the final image:
//     overwriting or whiteouting one name while another stays live costs nothing. Sparse files are measured by
//     their allocated data blocks, not their apparent length.
//
// A dead identity's bytes are reported on the path of the member that carried them, together with that path's
// occurrence count. The score is the share of all discovered bytes that are not wasted.
func imageEfficiency(ctx context.Context, img *image.Image) (float64, []Inefficiency, error) {
	countByPath, pathOrder, err := countPathOccurrences(ctx, img)
	if err != nil {
		return 0, nil, err
	}

	accounts, discovered, err := collectIdentityAccounts(ctx, img)
	if err != nil {
		return 0, nil, err
	}

	live, err := liveIdentities(ctx, img)
	if err != nil {
		return 0, nil, err
	}

	wasteByPath := make(map[file.Path]uint64)
	var wasted int64
	for id, account := range accounts {
		if live[id] {
			continue
		}
		wasted += account.bytes
		wasteByPath[account.carrier] += uint64(account.bytes)
	}

	var inefficiencies []Inefficiency
	for _, p := range pathOrder {
		bytes := wasteByPath[p]
		if bytes == 0 {
			continue
		}
		count := countByPath[p]
		if count == 0 {
			// every dead carrier was added in some layer, so this only guards an unexpected accounting gap
			count = 1
		}
		inefficiencies = append(inefficiencies, Inefficiency{Path: string(p), Count: count, SizeBytes: bytes})
	}

	sort.Slice(inefficiencies, func(i, j int) bool {
		a, b := inefficiencies[i], inefficiencies[j]
		if a.SizeBytes != b.SizeBytes {
			return a.SizeBytes > b.SizeBytes
		}
		return a.Path < b.Path
	})

	score := 1.0
	if discovered != 0 {
		score = float64(discovered-wasted) / float64(discovered)
	}
	return score, inefficiencies, nil
}

// countPathOccurrences walks each layer's own tree and counts, per path, every add and every removal a later
// layer performs. It returns the counts and the paths in first-seen order for deterministic reporting.
func countPathOccurrences(ctx context.Context, img *image.Image) (map[file.Path]int, []file.Path, error) {
	countByPath := make(map[file.Path]int)
	var pathOrder []file.Path

	count := func(p file.Path) {
		if _, seen := countByPath[p]; !seen {
			pathOrder = append(pathOrder, p)
		}
		countByPath[p]++
	}

	for i, l := range img.Layers {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		// paths of this layer that may hide lower paths: whiteout targets, opaque dirs and non-dirs
		var roots []file.Path
		err := layertree.Walk(l.Tree, nil, func(n *filenode.FileNode, leaf bool) error {
			p := n.RealPath
			if p.IsWhiteout() {
				// for an opaque marker this is the dir it sits in
				target, err := p.UnWhiteoutPath()
				if err != nil {
					return err
				}
				roots = append(roots, target)
				return nil
			}
			if !leaf {
				return nil
			}
			if n.FileType != file.TypeDirectory {
				roots = append(roots, p)
			}
			count(p)
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("unable to walk layer %d: %w", i, err)
		}
		if i == 0 {
			continue
		}
		for _, p := range removedPaths(img.Layers[i-1].SquashedTree, l.SquashedTree, roots) {
			if _, seen := countByPath[p]; !seen {
				pathOrder = append(pathOrder, p)
			}
			countByPath[p]++
		}
	}
	return countByPath, pathOrder, nil
}

// collectIdentityAccounts walks every layer's own tree and registers each distinct tar data section once,
// keyed by data identity. The total returned is every data byte the layer blobs carry (the discovered set).
//
// A same-layer duplicate tar member collapses to one catalog ref before this sees it, so such a member counts
// once; its physically duplicated data section is not observable through the catalog (a known limitation, and
// no mainstream builder emits duplicate members).
func collectIdentityAccounts(ctx context.Context, img *image.Image) (map[file.ID]*identityAccount, int64, error) {
	accounts := make(map[file.ID]*identityAccount)
	var discovered int64

	for _, l := range img.Layers {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		err := layertree.Walk(l.Tree, nil, func(n *filenode.FileNode, _ bool) error {
			if n.Reference == nil {
				return nil
			}
			identity, ok := layertree.ResolveIdentity(img, l.Tree, n.Reference)
			if !ok {
				// header-only entry, or a hardlink stereoscope could not adopt: no data to count
				return nil
			}
			if _, seen := accounts[identity.ID()]; seen {
				return nil
			}
			hdr, hdrOK := layertree.Header(img, n.Reference)
			if !hdrOK {
				return nil
			}
			bytes := layertree.AllocatedSize(hdr)
			accounts[identity.ID()] = &identityAccount{bytes: bytes, carrier: n.RealPath}
			discovered += bytes
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}
	return accounts, discovered, nil
}

// liveIdentities is the set of data identities reachable through some name in the final image. It walks the
// final squashed tree, which already has every whiteout and opaque marker applied, so no whiteout special
// casing is needed: a lower identity simply fails this membership test when all its names were hidden.
func liveIdentities(ctx context.Context, img *image.Image) (map[file.ID]bool, error) {
	live := make(map[file.ID]bool)
	err := layertree.Walk(img.SquashedTree(), nil, func(n *filenode.FileNode, _ bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if n.Reference == nil {
			return nil
		}
		// resolve against the layer that owns this ref, since a hardlink's binding is fixed within that layer
		owner := img.FileCatalog.Layer(*n.Reference)
		if owner == nil {
			return nil
		}
		identity, ok := layertree.ResolveIdentity(img, owner.Tree, n.Reference)
		if ok {
			live[identity.ID()] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return live, nil
}

// removedPaths lists the paths at or under roots in the lower squashed tree that are gone from the upper one.
func removedPaths(lower, upper filetree.Reader, roots []file.Path) []file.Path {
	lt, ut := lower.TreeReader(), upper.TreeReader()
	seen := make(map[file.Path]bool)
	var removed []file.Path
	var visit func(node.Node)
	visit = func(n node.Node) {
		p := n.(*filenode.FileNode).RealPath
		if seen[p] {
			return
		}
		seen[p] = true
		if ut.Node(n.ID()) == nil {
			removed = append(removed, p)
		}
		for _, child := range lt.Children(n) {
			visit(child)
		}
	}
	for _, root := range roots {
		if n := lt.Node(filenode.IDByPath(root)); n != nil {
			visit(n)
		}
	}
	return removed
}
