// Package image is the image domain: format-agnostic transcoding plus the
// avatar feature built on top of it. It depends on internal/oss for object
// storage and on internal/store for user metadata; it never depends on
// internal/auth.
package image

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/image/draw"

	// Register every decoder available to image.Decode. The standard library
	// image package registers nothing by itself: jpeg, png and gif register
	// in their own init functions, as do the x/image extensions below.
	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	stdimage "image"
)

var (
	// ErrImageTooLarge is returned when a source image exceeds the maximum
	// dimension allowed by the caller.
	ErrImageTooLarge = errors.New("image: source dimensions exceed the limit")
	// ErrNotAnImage is returned when the input cannot be decoded into a
	// bitmap by any registered decoder.
	ErrNotAnImage = errors.New("image: not a decodable image")
)

// ImageConverter encodes a bitmap into a specific image format. Each target
// format gets one implementation (JPEGConverter today, a future
// WebPConverter...); format-specific tradeoffs (alpha handling, quality)
// live inside the implementation, so the transcoding pipeline never needs to
// know which format it is producing.
type ImageConverter interface {
	// Encode writes img to w in the target format.
	Encode(w io.Writer, img stdimage.Image) error
	// Extension is the conventional file extension without the dot, e.g. "jpg".
	Extension() string
	// ContentType is the MIME type, e.g. "image/jpeg".
	ContentType() string
}

// Transcode is the format-agnostic transcoding pipeline: it decodes src into
// a bitmap (rejecting images whose width or height exceeds maxDim when
// maxDim > 0), center-crops and scales it to size×size, and hands the result
// to conv for encoding. Adding a new output format only requires a new
// ImageConverter; the pipeline and its callers stay unchanged.
//
// The whole input is read into memory first: DecodeConfig consumes the
// leading bytes of the stream (magic + header), so decoding must start from
// a fresh reader. Avatar uploads are already bounded by the handler's
// MaxBytesReader, so this is a small, fixed cost here.
func Transcode(src io.Reader, conv ImageConverter, size, maxDim int) ([]byte, error) {
	data, err := io.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf("image: read: %w", err)
	}
	if maxDim > 0 {
		cfg, _, err := stdimage.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotAnImage, err)
		}
		if cfg.Width > maxDim || cfg.Height > maxDim {
			return nil, ErrImageTooLarge
		}
	}
	img, _, err := stdimage.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotAnImage, err)
	}

	scaled := centerCropScale(img, size)
	var buf bytes.Buffer
	if err := conv.Encode(&buf, scaled); err != nil {
		return nil, fmt.Errorf("image: encode: %w", err)
	}
	return buf.Bytes(), nil
}

// centerCropScale center-crops img to the largest centered square and scales
// it to size×size with CatmullRom (high quality, suitable for avatars and
// other small images).
func centerCropScale(img stdimage.Image, size int) stdimage.Image {
	b := img.Bounds()
	side := min(b.Dx(), b.Dy())
	rect := stdimage.Rect(
		b.Min.X+(b.Dx()-side)/2,
		b.Min.Y+(b.Dy()-side)/2,
		b.Min.X+(b.Dx()-side)/2+side,
		b.Min.Y+(b.Dy()-side)/2+side,
	)

	dst := stdimage.NewNRGBA(stdimage.Rect(0, 0, size, size))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, rect, draw.Over, nil)
	return dst
}
