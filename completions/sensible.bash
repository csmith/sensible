# bash completion for sensible

_sensible_hosts() {
    local dir=${1/#\~/$HOME}
    sed -n 's/^\([A-Za-z0-9_.-]\{1,\}\):.*/\1/p' "$dir"/hosts.d/*.yml 2>/dev/null | sort -u
}

_sensible() {
    local cur=${COMP_WORDS[COMP_CWORD]} end=$COMP_CWORD prev i w
    COMPREPLY=()

    # Bash splits --flag=value into three words; find where the word being
    # completed starts, and the flag it's a value of, if any.
    if [[ $cur == = ]]; then
        cur= end=$((COMP_CWORD - 1)) prev=${COMP_WORDS[COMP_CWORD - 1]}
    elif [[ ${COMP_WORDS[COMP_CWORD - 1]} == = ]]; then
        end=$((COMP_CWORD - 2)) prev=${COMP_WORDS[COMP_CWORD - 2]}
    else
        prev=${COMP_WORDS[COMP_CWORD - 1]}
    fi

    local config=${SENSIBLE_CONFIG:-.} cmd=
    local -a args=()
    for ((i = 1; i < end; i++)); do
        w=${COMP_WORDS[i]}
        if [[ ${COMP_WORDS[i + 1]} == = ]]; then
            w+==${COMP_WORDS[i + 2]}
            i=$((i + 2))
        fi
        if [[ -z $cmd ]]; then
            case $w in
                -config | --config) config=${COMP_WORDS[++i]} ;;
                -config=* | --config=*) config=${w#*=} ;;
                -*) ;;
                *) cmd=$w ;;
            esac
        else
            case $w in
                -user | --user | -host-key | --host-key) ((i++)) ;;
                -*) ;;
                *) args+=("$w") ;;
            esac
        fi
    done

    if [[ -z $cmd ]]; then
        case $prev in
            -config | --config)
                COMPREPLY=($(compgen -d -- "$cur"))
                return
                ;;
        esac
        if [[ $cur == -* ]]; then
            COMPREPLY=($(compgen -W '--config --debug' -- "$cur"))
        else
            COMPREPLY=($(compgen -W 'bootstrap apply facts secret' -- "$cur"))
        fi
        return
    fi

    case $prev in
        -user | --user | -host-key | --host-key) [[ $cmd == bootstrap ]] && return ;;
    esac

    case $cmd in
        bootstrap)
            if [[ $cur == -* ]]; then
                COMPREPLY=($(compgen -W '--user --rotate --host-key' -- "$cur"))
            elif ((${#args[@]} == 0)); then
                COMPREPLY=($(compgen -W "$(_sensible_hosts "$config")" -- "$cur"))
            fi
            ;;
        apply | facts)
            if [[ $cur == -* ]]; then
                [[ $cmd == apply ]] && COMPREPLY=($(compgen -W '--yes' -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$(_sensible_hosts "$config")" -- "$cur"))
            fi
            ;;
        secret)
            if ((${#args[@]} == 0)); then
                [[ $cur != -* ]] && COMPREPLY=($(compgen -W 'encrypt show' -- "$cur"))
            elif [[ ${args[0]} == encrypt ]]; then
                [[ $cur == -* ]] && COMPREPLY=($(compgen -W '--raw' -- "$cur"))
            elif [[ ${args[0]} == show && ${#args[@]} == 1 ]]; then
                compopt -o filenames 2>/dev/null
                COMPREPLY=($(compgen -f -- "$cur"))
            fi
            ;;
    esac
}

complete -F _sensible sensible
