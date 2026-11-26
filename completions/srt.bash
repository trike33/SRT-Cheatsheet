#!/usr/bin/env bash
# bash completion for srt (SRT-Cheatsheet).
#
# install.sh/update.sh install this automatically to
# $PREFIX/share/bash-completion/completions/srt when that directory is on
# bash-completion's search path (every modern distro's default). To use it
# without a fresh shell, source it directly:
#
#   source completions/srt.bash
#
# This asks the already-installed `srt` binary itself for both command
# names and each command's flags (its own -h output), rather than hard-
# coding a list here that would drift out of sync the moment a command or
# flag is added -- see _srt_commands/_srt_command_flags below. If srt isn't
# on PATH, or a lookup fails for any reason, completion just offers nothing
# for that word rather than erroring.

# _srt_commands prints every registered command name, one per line, parsed
# from srt's own top-level usage (stderr; see cmd/srt/main.go's usage()) --
# each command is listed as "    name<tab/spaces>summary" under a "  GROUP:"
# heading, so a line starting with exactly four spaces then a word is a
# command row and nothing else in that listing is.
_srt_commands() {
  command srt 2>&1 1>/dev/null | awk '/^    [A-Za-z0-9]/{print $1}'
}

# _srt_command_flags prints $1's own flag names (just "-name", no type or
# description), parsed the same way from `srt $1 -h`'s own output --
# internal/cli.PrintGroupedUsage (what every command's -h goes through)
# always indents a flag's row with exactly three spaces then "-name", so
# that's the one pattern this looks for.
_srt_command_flags() {
  command srt "$1" -h 2>&1 1>/dev/null | awk '/^   -/{print $1}'
}

_srt() {
  local cur prev cmd i
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD - 1]}"

  # Walk past any global flag (-rate N / -save / -db PATH) to find the
  # subcommand, the same left-to-right scan cmd/srt/main.go's own
  # applyGlobalFlags does before dispatch.
  cmd=""
  i=1
  while [ "$i" -lt "$COMP_CWORD" ]; do
    case "${COMP_WORDS[$i]}" in
      -rate | -db)
        i=$((i + 2))
        continue
        ;;
      -save)
        i=$((i + 1))
        continue
        ;;
      -*)
        i=$((i + 1))
        continue
        ;;
      *)
        cmd="${COMP_WORDS[$i]}"
        break
        ;;
    esac
  done

  if [ -z "$cmd" ]; then
    if [ "$prev" = "-db" ]; then
      COMPREPLY=($(compgen -f -- "$cur"))
      return 0
    fi
    COMPREPLY=($(compgen -W "-rate -save -db $(_srt_commands)" -- "$cur"))
    return 0
  fi

  case "$cur" in
    -*)
      COMPREPLY=($(compgen -W "$(_srt_command_flags "$cmd")" -- "$cur"))
      ;;
    *)
      COMPREPLY=($(compgen -f -- "$cur"))
      ;;
  esac
}
complete -o bashdefault -o default -F _srt srt
