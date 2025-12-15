{
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.simpleFlake {
      inherit self nixpkgs;
      name = "aidr-go";
      shell = {pkgs ? import <nixpkgs>}:
        pkgs.mkShellNoCC {
          packages = with pkgs; [
            go
            golangci-lint
            pnpm
          ];

          env = {};

          shellHook = '''';
        };
    };
}
