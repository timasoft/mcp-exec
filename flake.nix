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

      nixosModules.mcp-secure-exec-base = import ./nixos/mcp-secure-exec.nix;

      nixosModules.mcp-secure-exec = { config, lib, pkgs, ... }: {
        imports = [ ./nixos/mcp-secure-exec.nix ];
        services.mcp-secure-exec.package = lib.mkDefault self.packages.${pkgs.system}.default;
      };

      nixosModule = self.nixosModules.mcp-secure-exec;

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
      nixosModules.mcp-secure-exec-base = import ./nixos/mcp-secure-exec.nix;
      nixosModules.mcp-secure-exec = { config, lib, pkgs, ... }: {
        imports = [ ./nixos/mcp-secure-exec.nix ];
      };
    };
}
