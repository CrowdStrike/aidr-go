{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  languages.go = {
    enable = true;
    version = "1.25.5";
  };
  starship.enable = true;
}
