//go:build linux && cgo

package main

/*
#cgo pkg-config: gtk+-3.0
#include <gtk/gtk.h>

// warpaltFixXFTDPI gives GTK a usable font resolution before the first
// WebView exists.
//
// GTK's gtk-xft-dpi property defaults to -1, its "not set" sentinel. On a
// bare Wayland session with no XSETTINGS manager nothing overrides it, and
// WebKitGTK feeds the sentinel straight into its device-scale computation:
// the page ends up with devicePixelRatio == -1/96, window.innerWidth goes
// negative (~ -96x the real width), every percentage width resolves against
// that garbage viewport and the whole layout collapses into a super-thin
// column. Setting a real value before the WebView is constructed makes
// WebKitGTK report sane numbers again.
static void warpaltFixXFTDPI(void) {
	if (!gtk_init_check(NULL, NULL)) {
		return;
	}
	GtkSettings *settings = gtk_settings_get_default();
	if (settings == NULL) {
		return;
	}
	gint64 dpi = -1;
	g_object_get(settings, "gtk-xft-dpi", &dpi, NULL);
	if (dpi <= 0) {
		g_object_set(settings, "gtk-xft-dpi", (gint64)(96 * 1024), NULL);
	}
}
*/
import "C"

// fixGTKDPI applies the workaround above. It is a no-op when GTK reports a
// positive resolution already (e.g. a desktop that ships an XSETTINGS
// daemon or a gtk-xft-dpi line in ~/.config/gtk-3.0/settings.ini).
func fixGTKDPI() { C.warpaltFixXFTDPI() }
