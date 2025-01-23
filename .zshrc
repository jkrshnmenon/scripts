# If you come from bash you might have to change your $PATH.
# export PATH=$HOME/bin:/usr/local/bin:$PATH

# Path to your oh-my-zsh installation.
export ZSH="$HOME/.oh-my-zsh"

# Set name of the theme to load --- if set to "random", it will
# load a random theme each time oh-my-zsh is loaded, in which case,
# to know which specific one was loaded, run: echo $RANDOM_THEME
# See https://github.com/ohmyzsh/ohmyzsh/wiki/Themes
ZSH_THEME="geoffgarside"

# Set list of themes to pick from when loading at random
# Setting this variable when ZSH_THEME=random will cause zsh to load
# a theme from this variable instead of looking in $ZSH/themes/
# If set to an empty array, this variable will have no effect.
# ZSH_THEME_RANDOM_CANDIDATES=( "robbyrussell" "agnoster" )

# Uncomment the following line to use case-sensitive completion.
# CASE_SENSITIVE="true"

# Uncomment the following line to use hyphen-insensitive completion.
# Case-sensitive completion must be off. _ and - will be interchangeable.
# HYPHEN_INSENSITIVE="true"

# Uncomment one of the following lines to change the auto-update behavior
# zstyle ':omz:update' mode disabled  # disable automatic updates
# zstyle ':omz:update' mode auto      # update automatically without asking
# zstyle ':omz:update' mode reminder  # just remind me to update when it's time

# Uncomment the following line to change how often to auto-update (in days).
# zstyle ':omz:update' frequency 13

# Uncomment the following line if pasting URLs and other text is messed up.
# DISABLE_MAGIC_FUNCTIONS="true"

# Uncomment the following line to disable colors in ls.
# DISABLE_LS_COLORS="true"

# Uncomment the following line to disable auto-setting terminal title.
# DISABLE_AUTO_TITLE="true"

# Uncomment the following line to enable command auto-correction.
# ENABLE_CORRECTION="true"

# Uncomment the following line to display red dots whilst waiting for completion.
# You can also set it to another string to have that shown instead of the default red dots.
# e.g. COMPLETION_WAITING_DOTS="%F{yellow}waiting...%f"
# Caution: this setting can cause issues with multiline prompts in zsh < 5.7.1 (see #5765)
# COMPLETION_WAITING_DOTS="true"

# Uncomment the following line if you want to disable marking untracked files
# under VCS as dirty. This makes repository status check for large repositories
# much, much faster.
DISABLE_UNTRACKED_FILES_DIRTY="true"

# Uncomment the following line if you want to change the command execution time
# stamp shown in the history command output.
# You can set one of the optional three formats:
# "mm/dd/yyyy"|"dd.mm.yyyy"|"yyyy-mm-dd"
# or set a custom format using the strftime function format specifications,
# see 'man strftime' for details.
HIST_STAMPS="dd.mm.yyyy"

# Would you like to use another custom folder than $ZSH/custom?
# ZSH_CUSTOM=/path/to/new-custom-folder

# Which plugins would you like to load?
# Standard plugins can be found in $ZSH/plugins/
# Custom plugins may be added to $ZSH_CUSTOM/plugins/
# Example format: plugins=(rails git textmate ruby lighthouse)
# Add wisely, as too many plugins slow down shell startup.
plugins=(
	git
       	docker 
	zsh-autocomplete
	zsh-autosuggestions 
	zsh-syntax-highlighting
	fzf-zsh-plugin
)

source $ZSH/oh-my-zsh.sh

# User configuration

# export MANPATH="/usr/local/man:$MANPATH"

# You may need to manually set your language environment
# export LANG=en_US.UTF-8

# Preferred editor for local and remote sessions
# if [[ -n $SSH_CONNECTION ]]; then
#   export EDITOR='vim'
# else
#   export EDITOR='mvim'
# fi
export EDITOR='vim'

# Compilation flags
# export ARCHFLAGS="-arch x86_64"

# Set personal aliases, overriding those provided by oh-my-zsh libs,
# plugins, and themes. Aliases can be placed here, though oh-my-zsh
# users are encouraged to define aliases within the ZSH_CUSTOM folder.
# For a full list of active aliases, run `alias`.
#
# Example aliases
alias zshconfig="vim ~/.zshrc"
alias ohmyzsh="vim ~/.oh-my-zsh"
alias reload="source ~/.zshrc"
alias aslr="echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
alias fuzz="sudo su -c 'echo core >/proc/sys/kernel/core_pattern && cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor'"
alias flex="pushd ~/Downloads/ida8.4/flexlm 1>/dev/null 2>/dev/null && ./run.sh && popd 1>/dev/null 2>/dev/null"
alias doup="docker compose up "
alias dodown="docker compose down "
alias honeynut="sudo openvpn --config $HOME/Documents/arbiter.conf &"

# export MANPAGER="sh -c 'col -bx | bat -l man -p'"
export BAT_THEME="Monokai Extended Bright"
source $HOME/.local/bin/virtualenvwrapper.sh
export WORKON_HOME=$HOME/.virtualenvs
export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python

source $HOME/.cargo/env

export PATH=$PATH:$HOME/.local/bin:$HOME/.rbenv/bin

eval $(thefuck --alias)
eval $(thefuck --alias FUCK)
setopt rmstarsilent
export OPENAI_API_KEY="BAZINGA!"
export GOROOT=$HOME/.local/go
export PATH=$GOROOT/bin:$PATH

pd_logs () {
	ID=$1
	pd cat $ID $(pd ls $ID)
}

# Pydatatask
alias pdlogs="pd_logs "

# Docker
alias doup="docker compose up "
alias dodown="docker compose down "
alias doprune="docker network prune -f"
alias dattach="d-attach"
alias dstop="d-stop-container"
alias drm="d-rm"
alias drmi="d-image-rm"
alias dlogs="d-logs"

# File search
alias frg="fzf-grep-edit "
alias fvim="fzf-find-edit"

# Kubernetes
alias fpods="fzf-browse-pods"

# Misc
alias fkill="fzf-kill"

alias zotero="/home/jay/Downloads/Zotero_linux-x86_64/zotero"
alias pwncollege="scp -r dojo:/challenge/ . && mv challenge/* . && rmdir challenge"

# Added by `rbenv init` on Thu Jul 18 11:34:05 AM MST 2024
eval "$(rbenv init - --no-rehash zsh)"

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion
alias vpn_start="connect_vpn"
alias vpn_stop="/opt/cisco/secureclient/bin/vpn disconnect"

# Disable semi-colon in zsh history search
zstyle ':autocomplete:*' insert-separator false
# Enter from history search submits command
# bindkey -M menuselect '^M' .accept-line
# Don't auto expand ~ to home folder
zstyle ':completion:*' expand 'false'
ZSH_AUTOCOMPLETE_IGNORE_COMPLETIONS_FOR="~"
