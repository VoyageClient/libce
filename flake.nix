{
  description = "An implementation of the Double Ratchet cryptographic ratchet";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # We can't use the current stable release because of
  # https://github.com/emscripten-core/emscripten/issues/16913
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    let
      localOverlay = import ./nix/overlay.nix;
      pkgsForSystem = system: import nixpkgs {
        inherit system;
        overlays = [
          localOverlay
        ];
      };
    in (
      # some systems cause issues, e.g. i686-linux is unsupported by gradle,
      # which causes "nix flake check" to fail. Investigate more later, but for
      # now, we will just allow x86_64-linux
      flake-utils.lib.eachSystem [ "x86_64-linux" ] (system: rec {
        legacyPackages = pkgsForSystem system;
        checks = {
          inherit (legacyPackages) olm-gcc-cmake olm-clang-cmake olm-gcc-make;
        };
      }
    ));
}
