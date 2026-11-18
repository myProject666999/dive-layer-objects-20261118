package layertree

import (
	"archive/tar"
	"strconv"
	"strings"
)

// paxSparseMap is the PAX record holding the GNU sparse fragment map as comma separated
// "offset,length" pairs. Go's tar reader populates it for GNU sparse formats 0.0 and 0.1. Format
// 1.0 carries the map in a following data block that the reader consumes, so it never reaches
// PAXRecords: an entry of that shape is indistinguishable here from a plain file.
const paxSparseMap = "GNU.sparse.map"

// AllocatedSize is the number of data bytes the tar member actually stores in the layer blob, as
// opposed to the apparent (logical) size the header reports for the extracted file.
//
// A header-only member (hardlink, symlink, dir, device, fifo) has no data section, so it allocates
// nothing. A GNU PAX sparse regular file allocates only the mapped data fragments: a file whose
// apparent length is a gigabyte can allocate a few kilobytes. Everything else allocates hdr.Size.
// The apparent length stays on hdr.Size and is what display surfaces; waste and efficiency accounting
// uses this value so it reflects bytes really stuck in the layer.
//
// A sparse map that cannot be parsed, or a GNU 1.0 sparse entry whose map the tar reader does not
// surface, falls back to hdr.Size rather than undercounting.
func AllocatedSize(hdr *tar.Header) int64 {
	if hdr == nil {
		return 0
	}
	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeRegA, tar.TypeGNUSparse:
		if n, ok := sparseAllocated(hdr); ok {
			return n
		}
		return hdr.Size
	default:
		// links, dirs and devices carry no data section in a tar
		return 0
	}
}

// IsSparse reports whether hdr describes a GNU sparse file whose fragment map the tar reader
// exposed. A GNU 1.0 sparse entry is not detectable from the header and reports false.
func IsSparse(hdr *tar.Header) bool {
	if hdr == nil {
		return false
	}
	_, ok := sparseAllocated(hdr)
	return ok
}

// sparseAllocated sums the fragment lengths in PAXRecords["GNU.sparse.map"]. ok is false when the
// map is absent (a plain file, or GNU 1.0 sparse), malformed, has an odd number of fields, a
// non-numeric field, or a sum that does not fit in int64, leaving the caller to use hdr.Size.
func sparseAllocated(hdr *tar.Header) (n int64, ok bool) {
	raw := hdr.PAXRecords[paxSparseMap]
	if raw == "" {
		return 0, false
	}
	fields := strings.Split(raw, ",")
	if len(fields) == 0 || len(fields)%2 != 0 {
		return 0, false
	}
	var total int64
	for i := 0; i < len(fields); i += 2 {
		offset, err := strconv.ParseInt(fields[i], 10, 64)
		if err != nil || offset < 0 {
			return 0, false
		}
		length, err := strconv.ParseInt(fields[i+1], 10, 64)
		if err != nil || length < 0 {
			return 0, false
		}
		// guard against overflow when accumulating
		if total > maxInt64-length {
			return 0, false
		}
		total += length
	}
	return total, true
}

const maxInt64 = int64(^uint64(0) >> 1)
