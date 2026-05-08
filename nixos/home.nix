{ config, pkgs, ... }:

{
  home.username = "jay";
  home.homeDirectory = "/home/jay";

  # This value should match the home-manager release you installed.
  # Check `man home-configuration.nix` or the release notes for details.
  home.stateVersion = "25.11";

  home.file = {
    ".config/niri/config.kdl".source = ./niri/config.kdl;

    ".config/waybar/config".source = ./waybar/config;
    ".config/waybar/style.css".source = ./waybar/style.css;
    ".config/waybar/scripts/power-profile-cycle.sh" = {
      source = ./waybar/scripts/power-profile-cycle.sh;
      executable = true;
    };

    ".config/ghostty/config".source = ./ghostty/config;

    ".config/swaylock/config".source = ./swaylock/config;
  };

  # Let home-manager manage itself.
  programs.home-manager.enable = true;
}
