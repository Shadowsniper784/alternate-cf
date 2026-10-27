{
  description = "warpalt — Nix flake for building the Cloudflare One (WARP) client";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
  let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
  in
  {
    packages.${system} = {
      default = self.packages.${system}.warpalt;

      warpalt = pkgs.buildGo127Module {
        pname = "warpalt";
        version = "0.1.0";
        src = ./.;

        # The production build tags are mandatory for Wails v2 (see build.sh).
        tags = [ "production" "webkit2_41" ];

        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.webkitgtk_4_1 pkgs.gtk3 ];

        # Hash of the vendored module set (see `nix-prefetch` / the
        # "got:" value from a failed build after a dependency change).
        vendorHash = null;

        meta = with pkgs.lib; {
          description = "Cloudflare One (WARP) client with a native UI";
          license = licenses.gpl3Only;
          platforms = [ "x86_64-linux" ];
        };
      };

      warpaltd = pkgs.buildGo127Module {
        pname = "warpaltd";
        version = "0.1.0";
        src = ./.;

        # Pure Go; no Wails/WebKit build tags.
        subPackages = [ "cmd/warpaltd" ];
        env.CGO_ENABLED = "0";
        vendorHash = null;

        meta = with pkgs.lib; {
          description = "warpalt privileged tunnel service";
          license = licenses.gpl3Only;
          platforms = [ "x86_64-linux" ];
        };
      };
    };

    devShells.${system} = {
      default = pkgs.mkShell {
        buildInputs = [
          pkgs.git
          pkgs.go_1_27
          pkgs.nodejs
          pkgs.pkg-config
          pkgs.webkitgtk_4_1
          pkgs.gtk3
          pkgs.glib
          pkgs.gobject-introspection
        ];
        shellHook = ''
          export CGO_ENABLED=1
          export GOFLAGS="-mod=readonly"
          export PATH=$PATH:$HOME/go/bin
          if ! command -v wails >/dev/null 2>&1; then
            echo "Installing wails CLI..."
            go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.0 2>/dev/null || true
          fi
          echo "warpalt dev shell ready. Use 'wails dev' for hot reload development."
        '';
      };
    };
  };
}
