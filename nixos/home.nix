{ config, pkgs, ... }:

let
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
in
{
  home.username = "jay";
  home.homeDirectory = "/home/jay";

  # This value should match the home-manager release you installed.
  # Check `man home-configuration.nix` or the release notes for details.
  home.stateVersion = "25.11";

  home.packages = with pkgs; [
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
  ];

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

    ".ptpython/config.py".source = ptpythonConfig;

    ".icons/default/index.theme".text = ''
      [Icon Theme]
      Name=Default
      Comment=Default cursor theme
      Inherits=Adwaita
    '';
  };

  home.sessionVariables = {
    XCURSOR_THEME = "Adwaita";
    XCURSOR_SIZE = "24";
  };

  programs.zsh = {
    enable = true;
    enableCompletion = true;
    autosuggestion.enable = true;
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

    # Set before oh-my-zsh is sourced
    envExtra = ''
      DISABLE_UNTRACKED_FILES_DIRTY="true"
      HIST_STAMPS="dd.mm.yyyy"
      # Load secrets (API keys etc.) from untracked file
      [ -f "$HOME/.zshenv.local" ] && source "$HOME/.zshenv.local"
    '';

    history = {
      size = 10000;
      path = "$HOME/.zsh_history";
      ignoreAllDups = true;
    };

    initContent = ''
      setopt RM_STAR_SILENT

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

    oh-my-zsh = {
      enable = true;
      plugins = [
        "git"
        "docker"
      ];
      theme = "geoffgarside";
    };

    plugins = [
      {
        name = "fzf-zsh-plugin";
        src = "${fzf-zsh-plugin}/share/zsh/plugins/fzf-zsh-plugin";
      }
    ];
  };

  # Let home-manager manage itself.
  programs.home-manager.enable = true;
}
