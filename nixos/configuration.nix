# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

let

  niri-taskbar = pkgs.rustPlatform.buildRustPackage {
    pname = "niri-taskbar";
    version = "unstable";
    src = pkgs.fetchFromGitHub {
      owner = "lawngnome";
      repo = "niri-taskbar";
      rev = "main";
      hash = "sha256-PN+7s3KnbIdUSs+PmY3A80x//tIQu2aqaW/vN7gXTRU=";
    };
    cargoHash = "sha256-WRc1+ZVhiIfmLHaczAPq21XudI08CgVhlIhVcf0rmSw=";
    nativeBuildInputs = with pkgs; [ pkg-config ];
    buildInputs = with pkgs; [ gdk-pixbuf atk gtk3 pango cairo ];
  };

  ptpythonConfig = pkgs.writeText "ptpython-config.py" ''
    from __future__ import unicode_literals
    from prompt_toolkit.filters import ViInsertMode
    from prompt_toolkit.key_binding.key_processor import KeyPress
    from prompt_toolkit.keys import Keys
    from pygments.token import Token
    from ptpython.layout import CompletionVisualisation

    __all__ = ("configure",)

    def configure(repl):
        repl.show_signature = True
        repl.show_docstring = True
        repl.show_meta_enter_message = True
        repl.completion_visualisation = CompletionVisualisation.POP_UP
        repl.completion_menu_scroll_offset = 0
        repl.show_line_numbers = True
        repl.show_status_bar = True
        repl.show_sidebar_help = True
        repl.highlight_matching_parenthesis = True
        repl.wrap_lines = True
        repl.enable_mouse_support = False
        repl.complete_while_typing = True
        repl.enable_fuzzy_completion = True
        repl.enable_dictionary_completion = True
        repl.vi_mode = True
        repl.paste_mode = False
        repl.prompt_style = "ipython"
        repl.insert_blank_line_after_output = True
        repl.enable_history_search = True
        repl.enable_auto_suggest = True
        repl.enable_open_in_editor = True
        repl.enable_system_bindings = True
        repl.confirm_exit = True
        repl.enable_input_validation = True
        repl.use_code_colorscheme("trac")
        repl.color_depth = "DEPTH_4_BIT"
        repl.enable_syntax_highlighting = True

    _custom_ui_colorscheme = {
        Token.Layout.Prompt: "bg:#eeeeff #000000 bold",
        Token.Toolbar.Status: "bg:#ff0000 #000000",
    }
  '';

  fzf-zsh-plugin = pkgs.stdenvNoCC.mkDerivation {
    name = "fzf-zsh-plugin";
    src = pkgs.fetchFromGitHub {
      owner = "unixorn";
      repo = "fzf-zsh-plugin";
      rev = "87d14584a9fe82e316173fdade8761dd53e45a62";
      sha256 = "0g2vq1ckbhpc1mv9vzqiclwxqc48xaagyr4050cjn4cw08vg3vwx";
    };
    patches = [ /home/jay/git_stuff/scripts/fzf-zsh-plugin.diff ];
    installPhase = ''
      mkdir -p $out/share/zsh/plugins/fzf-zsh-plugin
      cp -r . $out/share/zsh/plugins/fzf-zsh-plugin
    '';
  };
in
{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
      <home-manager/nixos>
    ];

  home-manager.useGlobalPkgs = true;
  home-manager.useUserPackages = true;
  home-manager.users.jay = import ./home.nix;

  # Bootloader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  networking.hostName = "nixos"; # Define your hostname.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Enable networking
  networking.networkmanager.enable = true;

  # Set your time zone.
  time.timeZone = "America/Phoenix";

  # Select internationalisation properties.
  i18n.defaultLocale = "en_US.UTF-8";

  i18n.extraLocaleSettings = {
    LC_ADDRESS = "en_US.UTF-8";
    LC_IDENTIFICATION = "en_US.UTF-8";
    LC_MEASUREMENT = "en_US.UTF-8";
    LC_MONETARY = "en_US.UTF-8";
    LC_NAME = "en_US.UTF-8";
    LC_NUMERIC = "en_US.UTF-8";
    LC_PAPER = "en_US.UTF-8";
    LC_TELEPHONE = "en_US.UTF-8";
    LC_TIME = "en_US.UTF-8";
  };

  # Enable the X11 windowing system.
  services.xserver.enable = true;

  # Enable the GNOME Desktop Environment.
  services.xserver.displayManager.gdm.enable = true;
  services.xserver.desktopManager.gnome.enable = true;

  # Configure keymap in X11
  services.xserver.xkb = {
    layout = "us";
    variant = "";
  };

  # Enable CUPS to print documents.
  services.printing.enable = true;

  # Enable sound with pipewire.
  services.pulseaudio.enable = false;
  security.rtkit.enable = true;
  security.sudo.wheelNeedsPassword = false;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    # If you want to use JACK applications, uncomment this
    #jack.enable = true;

    # use the example session manager (no others are packaged yet so this is enabled by default,
    # no need to redefine it in your config for now)
    #media-session.enable = true;
  };

  # Enable touchpad support (enabled default in most desktopManager).
  # services.xserver.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.jay = {
    isNormalUser = true;
    description = "Jay";
    extraGroups = [ "networkmanager" "wheel" "docker" ];
    packages = with pkgs; [
    #  thunderbird
    ];
    shell = pkgs.zsh;
  };

  # Install firefox.
  programs.firefox.enable = true;
  programs.niri.enable = true;
  programs.xwayland.enable = true;

  programs.git.enable = true;


  programs.zsh = {
    enable = true;
    enableCompletion = true;
    autosuggestions.enable = true;
    syntaxHighlighting.enable = true;

    shellAliases = {
      ll = "ls -l";
      edit = "sudo vim /etc/nixos/configuration.nix";
      update = "sudo nixos-rebuild switch";

      # Config shortcuts
      zshconfig = "vim ~/.zshrc";
      ohmyzsh = "vim ~/.oh-my-zsh";
      reload = "source ~/.zshrc";

      # Security / system
      aslr = "echo 0 | sudo tee /proc/sys/kernel/randomize_va_space";
      fuzz = "sudo su -c 'echo core >/proc/sys/kernel/core_pattern && cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor'";

      # Docker
      doup = "docker compose up";
      dodown = "docker compose down";
      devup = "COMPOSE_PROFILES=dev docker compose up";
      devdown = "COMPOSE_PROFILES=dev docker compose down";
      doprune = "docker network prune -f";
      dattach = "d-attach";
      dstop = "d-stop-container";
      drm = "d-rm";
      drmi = "d-image-rm";
      dlogs = "d-logs";

      # File search (fzf-zsh-plugin)
      fvim = "fzf-find-edit";
      frg = "fzf-grep-edit";
      fcode = "fzf-vscode";
      fcd = "fzf_cd";

      # Misc
      fkill = "fzf-kill";
    };

    # Set before oh-my-zsh is sourced (shellInit goes into .zshenv)
    shellInit = ''
      DISABLE_UNTRACKED_FILES_DIRTY="true"
      HIST_STAMPS="dd.mm.yyyy"
    '';

    histSize = 10000;
    histFile = "$HOME/.zsh_history";
    setOptions = [
      "HIST_IGNORE_ALL_DUPS"
      "RM_STAR_SILENT"
    ];

    interactiveShellInit = ''
      export DISPLAY=''${DISPLAY:-:0}
      export EDITOR='vim'
      export BAT_THEME="Monokai Extended Bright"
      export IDA_PATH=$HOME/Downloads/idapro-9.0
      export PATH=$PATH:$HOME/.local/bin

      export WORKON_HOME=$HOME/.virtualenvs
      export VIRTUALENVWRAPPER_PYTHON=${pkgs.python3}/bin/python3
      source ${pkgs.zsh-fzf-tab}/share/fzf-tab/fzf-tab.plugin.zsh
      source ${pkgs.python3Packages.virtualenvwrapper}/bin/virtualenvwrapper.sh

      # fzf_cd — fuzzy-find into a subdirectory
      fzf_cd() {
        x=$(find . -type d 2>/dev/null | fzf --query="''${*:-}" --no-multi --select-1 --exit-0)
        if [ -d "$x" ]; then
          cd $x
        fi
      }

      # pay-respects (thefuck replacement) — lazy-load on first use
      thefuck() {
        unfunction thefuck FUCK 2>/dev/null
        eval "$(command pay-respects --alias thefuck)"
        eval "$(command pay-respects --alias FUCK)"
        thefuck "$@"
      }
      FUCK() { thefuck "$@" }

      # nvm — lazy-load; nvm is managed outside Nix in ~/.nvm
      export NVM_DIR="$HOME/.nvm"
      _nvm_load() {
        unfunction nvm node npm npx 2>/dev/null
        [ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh"
        [ -s "$NVM_DIR/bash_completion" ] && source "$NVM_DIR/bash_completion"
      }
      nvm()  { _nvm_load; nvm "$@" }
      node() { _nvm_load; node "$@" }
      npm()  { _nvm_load; npm "$@" }
      npx()  { _nvm_load; npx "$@" }

      # rbenv
      eval "$(rbenv init - --no-rehash zsh)"

      # uv/uvx completions — regenerate only when the binary changes
      _uv_comp_cache="$HOME/.cache/zsh/uv_completion.zsh"
      if [[ ! -f "$_uv_comp_cache" || "$(command -v uv)" -nt "$_uv_comp_cache" ]]; then
        mkdir -p "''${_uv_comp_cache:h}"
        { uv generate-shell-completion zsh; uvx --generate-shell-completion zsh } > "$_uv_comp_cache"
      fi
      source "$_uv_comp_cache"
      unset _uv_comp_cache
    '';

    ohMyZsh = {
      enable = true;
      plugins = [
        "git"
        "docker"
        "fzf-zsh-plugin"
      ];
      theme = "geoffgarside";
      customPkgs = [ fzf-zsh-plugin ];
    };
  };

  # Bluetooth
  hardware.bluetooth.enable = true;
  services.blueman.enable = true;

  # Docker
  virtualisation.docker.enable = true;

  # Allow unfree packages
  nixpkgs.config.allowUnfree = true;
  environment.pathsToLink = [ "/lib" ];

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    (vim-full.customize {
      name = "vim";
      vimrcConfig = {
        packages.default = with vimPlugins; {
          start = [
            vim-airline
            vim-airline-themes
            gruvbox
            YouCompleteMe
            syntastic
            vim-latex-live-preview
            nerdtree
            vim-snippets
            ultisnips
            vim-surround
            supertab
            copilot-vim
            vim-lsp
          ];
        };
        customRC = ''
          set keyprotocol=
          set nocompatible
          filetype plugin indent on

          " Clipboard
          nnoremap <C-y> "+y
          vnoremap <C-y> "+y
          nnoremap <C-p> "+p
          vnoremap <C-p> "+p
          vnoremap Y "+y :call system('xclip -selection clipboard', @+)<CR>

          " NERDTree
          let g:NERDSpaceDelims = 1
          let g:NERDTrimTrailingWhitespace = 1
          let g:NERDTreeDirArrowExpandable = '▸'
          let g:NERDTreeDirArrowCollapsible = '▾'
          let g:NERDTreeNodeDelimiter = "\u00a0"
          nnoremap <leader>n :NERDTreeFocus<CR>
          nnoremap <leader>t :NERDTreeToggle<CR>
          nnoremap <leader>f :NERDTreeFind<CR>
          nnoremap <C-t> :NERDTreeToggle<CR>
          nnoremap <C-f> :NERDTreeFind<CR>
          autocmd StdinReadPre * let s:std_in=1
          autocmd VimEnter * NERDTree | if argc() > 0 || exists("s:std_in") | wincmd p | endif
          autocmd VimEnter * if argc() == 1 && isdirectory(argv()[0]) && !exists('s:std_in') |
            \ execute 'NERDTree' argv()[0] | wincmd p | enew | execute 'cd '.argv()[0] | endif
          autocmd BufEnter * if winnr('$') == 1 && exists('b:NERDTree') && b:NERDTree.isTabTree() | quit | endif
          autocmd BufEnter * if tabpagenr('$') == 1 && winnr('$') == 1 && exists('b:NERDTree') && b:NERDTree.isTabTree() | quit | endif

          " LaTeX live preview
          let g:livepreview_engine = 'xelatex'
          let g:livepreview_previewer = 'evince'
          autocmd Filetype tex setl updatetime=1

          " YouCompleteMe + UltiSnips + SuperTab
          let g:ycm_autoclose_preview_window_after_insertion = 1
          let g:ycm_key_list_select_completion = ['<C-n>', '<Down>']
          let g:ycm_key_list_previous_completion = ['<C-p>', '<Up>']
          let g:SuperTabDefaultCompletionType = '<C-n>'
          let g:UltiSnipsExpandTrigger = "<tab>"
          let g:UltiSnipsJumpForwardTrigger = "<tab>"
          let g:UltiSnipsJumpBackwardTrigger = "<s-tab>"
          let g:UltiSnipsEditSplit="vertical"

          " Appearance
          set encoding=utf-8
          set background=dark
          autocmd vimenter * ++nested colorscheme gruvbox
          let g:airline_theme='supernova'
          let g:airline_symbols_ascii = 1
          let g:airline_detect_modified=1

          " Indentation
          set tabstop=4
          set shiftwidth=4
          set expandtab

          " Rust
          let g:rustfmt_autosave = 1

          " Ruff LSP + format on save for Python
          if executable('ruff')
            au User lsp_setup call lsp#register_server({
              \ 'name': 'ruff',
              \ 'cmd': {server_info->['ruff', 'server']},
              \ 'allowlist': ['python'],
              \ 'workspace_config': {},
              \ })
          endif

          function! RuffFormat()
            let l:pos = getpos('.')
            let l:lines = getline(1, '$')
            let l:result = systemlist('ruff format -', l:lines)
            if v:shell_error == 0
              call setline(1, l:result)
              call deletebufline('%', len(l:result) + 1, '$')
            endif
            call setpos('.', l:pos)
          endfunction

          autocmd BufWritePre *.py call RuffFormat()

          " Terminal escape fix
          let &t_TI = ""
          let &t_TE = ""
        '';
      };
    })
    wget
    claude-code
    fzf
    zsh-fzf-tab
    cargo
    uv
    python3
    python3Packages.pip
    python3Packages.virtualenvwrapper
    go
    ghostty
    nerd-fonts.fira-code
    font-awesome
    roboto
    discord
    zoom-us
    xwayland-satellite
    btop
    vscode-fhs
    gcc
    clang
    llvm
    p7zip
    zip
    python3Packages.ptpython
    md-tui
    superfile
    yq-go
    csvlens
    niri-taskbar
    wdisplays
    pavucontrol
    networkmanagerapplet
    blueman
    fuzzel
    zenity
    swaybg
    waybar
    swaylock
    bat
    pay-respects
    rbenv
    xclip
    ruff
    google-cloud-sdk
    xfce.xfce4-power-manager
    mako
    libnotify
  ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  # services.openssh.enable = true;

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.activationScripts.ptpythonConfig.text = ''
    mkdir -p /home/jay/.ptpython
    ln -sf ${ptpythonConfig} /home/jay/.ptpython/config.py
  '';

  system.stateVersion = "25.11"; # Did you read the comment?

}
