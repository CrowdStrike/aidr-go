{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: {
  languages.go = {
    enable = true;
    version = "1.26.7";
  };

  git-hooks.hooks = {
    alejandra.enable = true;
    golangci-lint.enable = true;
  };
}
