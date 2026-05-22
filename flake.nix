{
  description = "Encrypted browser-state checkpoint project 'repossess' dev environment";

  inputs = {
    # TODO: bump to nixos-25.11 — crane emits a warning that it requires ≥25.11.
    # Do this when the Nix store cache is already cold to avoid a surprise 20-min rebuild.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, crane, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rustToolchain =
          pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
          buildInputs = with pkgs; [ ];
          nativeBuildInputs = with pkgs; [ pkg-config ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        repossess = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "repossess";
          doCheck = false;
        });
      in
      {
        packages = {
          default = repossess;
          repossess = repossess;
          chromium = pkgs.ungoogled-chromium;
        };

        apps.default = flake-utils.lib.mkApp { drv = repossess; };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            cargo-deny
            cargo-audit
            age
            minisign
            zstd
            jq
            ungoogled-chromium
            gh
          ];

          shellHook = ''
            export CHROMIUM_BIN=${pkgs.ungoogled-chromium}/bin/chromium
          '';
        };

        checks = {
          inherit repossess;

          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          fmt = craneLib.cargoFmt {
            src = commonArgs.src;
          };
        };
      });
}
