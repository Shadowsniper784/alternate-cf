{ pkgs ? import <nixpkgs> {} }:

pkgs.buildGoModule {
  pname = "warpalt";
  version = "0.1.0";
  src = ./.;

  # Wails v2 refuses to build without these tags.
  tags = [ "production" "webkit2_41" ];

  nativeBuildInputs = [ pkgs.pkg-config ];
  buildInputs = [ pkgs.webkitgtk_4_1 pkgs.gtk3 ];

  # The repository vendors its dependencies.
  vendorHash = null;

  meta = with pkgs.lib; {
    description = "Cloudflare One (WARP) client with a native UI";
    license = licenses.gpl3Only;
    platforms = [ "x86_64-linux" ];
  };
}
