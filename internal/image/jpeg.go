package image

import (
	"image/color"
	"image/jpeg"
	"io"

	stdimage "image"

	"golang.org/x/image/draw"
)

// JPEGConverter encodes bitmaps as JPEG. JPEG has no alpha channel, so
// images with a transparent channel are composited onto a white background
// first; otherwise the transparent areas would encode as black.
type JPEGConverter struct {
	// Quality is the JPEG quality in [0, 100]; 85 is a good default.
	Quality int
}

// Encode writes img to w as JPEG, compositing transparent images onto white
// first.
func (c JPEGConverter) Encode(w io.Writer, img stdimage.Image) error {
	if hasAlpha(img) {
		img = compositeWhite(img)
	}
	return jpeg.Encode(w, img, &jpeg.Options{Quality: c.Quality})
}

// Extension returns "jpg".
func (JPEGConverter) Extension() string { return "jpg" }

// ContentType returns "image/jpeg".
func (JPEGConverter) ContentType() string { return "image/jpeg" }

// hasAlpha reports whether the image's color model carries an alpha channel.
// Opaque images (YCbCr from JPEG, Gray, fully opaque palettes, ...) skip
// compositing entirely. Paletted images count as alpha-carrying when any
// palette entry is not fully opaque — a transparent palette entry with RGB
// 0 would otherwise encode as black in the JPEG output.
func hasAlpha(img stdimage.Image) bool {
	if pal, ok := img.ColorModel().(color.Palette); ok {
		for _, c := range pal {
			if _, _, _, a := c.RGBA(); a != 0xffff {
				return true
			}
		}
		return false
	}
	switch img.ColorModel() {
	case color.NRGBAModel, color.RGBAModel,
		color.NRGBA64Model, color.RGBA64Model,
		color.AlphaModel, color.Alpha16Model:
		return true
	}
	return false
}

// compositeWhite draws img over a solid white background, flattening any
// transparency. The result is an NRGBA image of the same bounds.
func compositeWhite(src stdimage.Image) stdimage.Image {
	dst := stdimage.NewNRGBA(src.Bounds())
	draw.Draw(dst, dst.Bounds(), &stdimage.Uniform{C: color.White}, stdimage.Point{}, draw.Src)
	draw.Draw(dst, dst.Bounds(), src, src.Bounds().Min, draw.Over)
	return dst
}
