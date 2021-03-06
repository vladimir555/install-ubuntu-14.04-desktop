##############################
# My super awesome zshrc.    #
##############################

# Environment and shell options.
#

setopt INC_APPEND_HISTORY SHARE_HISTORY HIST_IGNORE_DUPS HIST_IGNORE_ALL_DUPS HIST_REDUCE_BLANKS HIST_IGNORE_SPACE HIST_NO_STORE HIST_VERIFY
setopt EXTENDED_HISTORY HIST_SAVE_NO_DUPS HIST_EXPIRE_DUPS_FIRST HIST_FIND_NO_DUPS APPEND_HISTORY
setopt CORRECT MENUCOMPLETE ALL_EXPORT
setopt   notify globdots correct pushdtohome cdablevars autolist
setopt   correctall autocd recexact longlistjobs
setopt   autoresume histignoredups pushdsilent 
setopt   autopushd pushdminus extendedglob rcquotes mailwarning
unsetopt bgnice autoparamslash

# Modules
#
# Set hsitory stuff.
#
HISTFILE=$HOME/.zhistory
HISTSIZE=10000
SAVEHIST=10000

alias tetr='/home/volodja/workspace/shell/translate-en-to-ru.sh $1'
alias trte='/home/volodja/workspace/shell/translate-ru-to-en.sh $1'
alias less='/home/volodja/workspace/shell/less.sh $1'
alias ids='/home/volodja/workspace/shell/internet-duckduckgo-search.sh $1'
alias igs='/home/volodja/workspace/shell/internet-google-search.sh $1'
alias iys='/home/volodja/workspace/shell/internet-yandex-search.sh $1'
alias ims='/home/volodja/workspace/shell/internet-mail-search.sh $1'

# Set up must-have aliases and alias file.
#
alias ls='clear && ls --color=auto'
alias ll='ls -lh'
alias la='ls -a'
alias l='ls'
export GREP_OPTIONS='--color=auto'
export GREP_COLOR='1;33'


# Key-bindings.
#

autoload -U compinit
compinit
bindkey '^[OH' beginning-of-line
bindkey '^[OF' end-of-line
bindkey '^I' complete-word # complete on tab, leave expansion to _expand
bindkey "\e[5~"  history-search-backward
bindkey "\e[6~"  history-search-forward


# Auto-completion settings.
#

zstyle ':completion::complete:*' use-cache on
zstyle ':completion::complete:*' cache-path ~/.zsh/cache/$HOST
zstyle ':completion:*' list-colors ${(s.:.)LS_COLORS}
zstyle ':completion:*' list-prompt '%SAt %p: Hit TAB for more, or the character to insert%s'
zstyle ':completion:*' menu select=1 _complete _ignored _approximate
zstyle -e ':completion:*:approximate:*' max-errors \
    'reply=( $(( ($#PREFIX+$#SUFFIX)/2 )) numeric )'
zstyle ':completion:*' select-prompt '%SScrolling active: current selection at %p%s'
zstyle ':completion:*::::' completer _expand _complete _ignored _approximate
zstyle -e ':completion:*:approximate:*' max-errors \
    'reply=( $(( ($#PREFIX+$#SUFFIX)/2 )) numeric )'
zstyle ':completion:*:expand:*' tag-order all-expansions
zstyle ':completion:*' verbose yes
zstyle ':completion:*:descriptions' format '%B%d%b'
zstyle ':completion:*:messages' format '%d'
zstyle ':completion:*:warnings' format 'No matches for: %d'
zstyle ':completion:*:corrections' format '%B%d (errors: %e)%b'
zstyle ':completion:*' group-name ''
zstyle ':completion:*' matcher-list 'm:{a-z}={A-Z}'
zstyle ':completion:*:*:-subscript-:*' tag-order indexes parameters
zstyle ':completion:*:*:kill:*:processes' list-colors '=(#b) #([0-9]#)*=0=01;31'
zstyle ':completion:*:*:kill:*:processes' command 'ps --forest -A -o pid,user,cmd'
zstyle ':completion:*:processes-names' command 'ps axho command' 

[[ -f /usr/bin/grc ]] && {
  alias ping="grc --colour=auto ping"
  alias traceroute="grc --colour=auto traceroute"
  alias make="grc --colour=auto make"
  alias diff="grc --colour=auto diff"
  alias cvs="grc --colour=auto cvs"
  alias netstat="grc --colour=auto netstat"
}

###   Handy Extract Program

extract () {
    if [ -f $1 ] ; then
        case $1 in
            *.tar.bz2)   tar xvjf $1        ;;
            *.tar.gz)    tar xvzf $1     ;;
            *.bz2)       bunzip2 $1       ;;
            *.rar)       unrar x $1     ;;
            *.gz)        gunzip $1     ;;
            *.tar)       tar xvf $1        ;;
            *.tbz2)      tar xvjf $1      ;;
            *.tgz)       tar xvzf $1       ;;
            *.zip)       unzip $1     ;;
            *.Z)         uncompress $1  ;;
            *.7z)        7z x $1    ;;
            *)           echo "'$1' cannot be extracted via >extract<" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}




autoload -U colors
#colors

# See if we can use colors.
autoload colors zsh/terminfo
if [[ "$terminfo[colors]" -ge 8 ]]; then
   colors
fi
   for color in RED GREEN YELLOW BLUE MAGENTA CYAN WHITE; do
   eval PR_$color='%{$terminfo[bold]$fg[${(L)color}]%}'
   eval PR_LIGHT_$color='%{$fg[${(L)color}]%}'
   (( count = $count + 1 ))
done
   PR_NO_COLOUR="%{$terminfo[sgr0]%}"

local blue_op=""$PR_BLUE""$PR_NO_COLOUR""
local blue_cp=""$PR_BLUE""$PR_NO_COLOUR""
local path_p="${blue_op}$PR_MAGENTA%/$PR_NO_COLOUR${blue_cp}%b"
local user_host="${blue_op}%B$PR_GREEN%n@%m$PR_NO_COLOUR${blue_cp}"
PROMPT="${user_host}: ${path_p}$PR_BLUE$PR_NO_COLOUR "
RPROMPT="%B%*%b"
