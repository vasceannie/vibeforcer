"""Shell completion scripts for isx / vibeforcer search."""
from __future__ import annotations

from vibeforcer.search.config import IsxError

BASH_COMPLETION = r'''_isx() {
  local cur prev words cword
  _init_completion || return

  local commands="init doctor models use list add search remove sync reindex completions"

  if [[ $cword -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    return
  fi

  prev="${words[cword-1]}"
  case "${words[1]}" in
    init)
      COMPREPLY=( $(compgen -W "--provider --base-url --model --api-key-env --api-key-value --binary --islands-config --integration --skill-target --skill-name --opencode-plugin-path --opencode-config --force litellm ollama none skill opencode-tool claude opencode both" -- "$cur") )
      ;;
    models)
      COMPREPLY=( $(compgen -W "--all --json" -- "$cur") )
      ;;
    use)
      COMPREPLY=( $(compgen -W "--force" -- "$cur") )
      ;;
    list)
      COMPREPLY=( $(compgen -W "--json" -- "$cur") )
      ;;
    remove)
      COMPREPLY=( $(compgen -W "--force" -- "$cur") )
      ;;
    sync)
      COMPREPLY=()
      ;;
    reindex)
      COMPREPLY=()
      ;;
    completions)
      COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
      ;;
    *)
      COMPREPLY=()
      ;;
  esac
}
complete -F _isx isx
complete -F _isx vfc
'''

ZSH_COMPLETION = r'''#compdef isx vfc

_isx() {
  local -a commands
  commands=(
    'init:write wrapper and islands configs'
    'doctor:check runtime config and endpoint reachability'
    'models:list available embedding models'
    'use:switch to a different embedding model'
    'list:list locally known indexes'
    'add:index a repository URL'
    'search:search indexed repositories'
    'remove:remove an index by name or repo identity'
    'sync:sync one or more indexes with upstream'
    'reindex:remove and rebuild an index from its clone URL'
    'completions:print shell completions'
  )

  local context state line
  _arguments -C \
    '1:command:->command' \
    '*::arg:->args'

  case $state in
    command)
      _describe 'command' commands
      ;;
    args)
      case $words[2] in
        init)
          _arguments \
            '--provider[provider to target]:provider:(litellm ollama)' \
            '--base-url[OpenAI-compatible base URL]:url:_urls' \
            '--model[embedding model name]:model:' \
            '--api-key-env[env var for OPENAI_API_KEY]:env var:' \
            '--api-key-value[fixed API key value]:api key:' \
            '--binary[islands binary]:binary:_files' \
            '--islands-config[path to islands config]:path:_files' \
            '--integration[optional integration scaffold]:mode:(none skill opencode-tool)' \
            '--skill-target[where to install generated skill]:target:(claude opencode both)' \
            '--skill-name[name for the generated skill]:skill name:' \
            '--opencode-plugin-path[path to generated OpenCode plugin]:path:_files' \
            '--opencode-config[path to opencode.json]:path:_files' \
            '--force[overwrite existing config files]'
          ;;
        models)
          _arguments '--all[show all models]' '--json[print JSON]'
          ;;
        use)
          _arguments '--force[skip remote model validation]' '1:model:'
          ;;
        list)
          _arguments '--json[print machine-readable JSON]'
          ;;
        remove)
          _arguments '--force[skip confirmation prompt]' '1:index or repo:'
          ;;
        sync)
          _arguments '*:index:'
          ;;
        reindex)
          _arguments '1:index or repo:'
          ;;
        completions)
          _arguments '1:shell:(bash zsh)'
          ;;
      esac
      ;;
  esac
}

_isx "$@"
'''


def print_completion(shell: str) -> int:
    """Print a shell completion script and return 0, or raise on bad shell."""
    if shell == "bash":
        print(BASH_COMPLETION, end="")
        return 0
    if shell == "zsh":
        print(ZSH_COMPLETION, end="")
        return 0
    raise IsxError(f"unsupported shell: {shell}")
