#!/usr/bin/env zsh
source $HOME/.zshrc
autoload -U colors
colors

BIG='\033#9'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

success () {
  printf "[$fg[green]$bold_color"+"${reset_color}] $1\n"
}

if [ ! -d "$SCRIPT_DIR/.venv" ];
then
  success "installing and configuring venv"
  python -m venv "$SCRIPT_DIR/.venv"
  source "$SCRIPT_DIR/.venv/bin/activate"
  pip install --upgrade pip
  pip install pwntools
fi

check_alias=$(alias | grep "run='")
if [ -z $check_alias ];
then
  success "adding run alias"
  echo "alias run=\"source $SCRIPT_DIR/.venv/bin/activate; $SCRIPT_DIR/run\"" >> ~/.zshrc
fi

check_alias=$(alias | grep "pwninit='")
if [ -z $check_alias ];
then
  success "adding pwninit alias"
  echo "alias pwninit=\"source $SCRIPT_DIR/.venv/bin/activate; $SCRIPT_DIR/pwninit\"" >> ~/.zshrc
fi

success "all setup, good pwn"
