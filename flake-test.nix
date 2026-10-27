{
  description = "test";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  outputs = { self, nixpkgs }:
  let
    inherit (nixpkgs) pkgs;
    system = "x86_64-linux";
  in {
    packages = {
      warpalt = let
        inherit (pkgs) go;
      in
      stdenv.mkDerivation {
        pname = "warpalt";
        version = "0.1.0";
        src = ./.;
        buildPhase = ''
          ${go}/bin/go version > ${out}
        '';
        installPhase = '';
      };
    };
  };
}
