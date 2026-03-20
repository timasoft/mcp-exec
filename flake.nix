{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    naersk.url  = "github:nix-community/naersk";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, naersk, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };
      naerskLib = pkgs.callPackage naersk {};
      rustSrc = pkgs.rust.packages.stable.rustPlatform.rustLibSrc;

      mcp-secure-exec = naerskLib.buildPackage {
        src = ./.;
        nativeBuildInputs = [ pkgs.pkg-config ];
      };
    in {
      packages.default = mcp-secure-exec;
      packages.mcp-secure-exec = mcp-secure-exec;

      defaultPackage = mcp-secure-exec;

      nixosModules.default = import ./nixos/mcp-secure-exec.nix;
      nixosModules.mcp-secure-exec = self.nixosModules.default;

      nixosModule = self.nixosModules.default;

      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          fish
          cargo rustc rustfmt clippy rust-analyzer
        ];
        nativeBuildInputs = [ pkgs.pkg-config ];

        shellHook = ''
          if [ -z "$FISH_VERSION" ] && [ -z "$NO_AUTO_FISH" ]; then
            exec ${pkgs.fish}/bin/fish
          fi
        '';

        env.RUST_SRC_PATH = "${rustSrc}";
      };
    }) // {
      nixosModules.default = import ./nixos/mcp-secure-exec.nix;
      nixosModules.mcp-secure-exec = self.nixosModules.default;
    };
}
