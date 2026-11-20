#!/bin/sh
# .NET CVE Shield demo for imageservice: CVE-2018-1000210 (YamlDotNet < 5.0.0), a .NET CVE Shield
# that supports BLOCK. See section 14 of docs/vulnerabilities.md.
#
# Usage: ./dotnet-shield-demo.sh <command>
#   restart  restart imageservice (fresh agent, small logs) and clear evicted pods
#   warm     harmless YAML import, then wait until the agent holds the CVE-2018-1000210 shield
#   exploit  send the RCE payload (touch /tmp/pwned) and report BLOCKED or EXPLOITED
#   logs     agent evidence for CVE-2018-1000210: shield definition, Entry, Capability and block events
#   clean    remove /tmp/pwned from the pod

set -e
cd "$(dirname "$0")"

PORT="${PORT:-8081}"
CVE="CVE-2018-1000210"
LOGS=/contrast/data/logs
# INFO-level line the agent writes once it holds the shield for the library.
LOADED="CVE '$CVE' matched library"
NEEDS_DEBUG="(none, these lines need the agent log level at DEBUG)"
# The shield fields only appear in the DEBUG-level definition line.
SHIELD_FIELDS="grep -h 'Received a new CVE Shield definition' $LOGS/*Sensors*.log | grep '$CVE' | tail -n1 \\
    | grep -o -E '\"(Mode|MaxSupportedBehavior)\":\"[A-Z]+\"|\"Denied\":\\[[^]]*\\]' | sort -u | grep . \\
    || echo '$NEEDS_DEBUG'"
# Timestamp plus the event text, without the thread and logger columns or the long rule id.
EVENT_LINE="sed -E 's/^([0-9-]+ [0-9:.]+).*(Report(Entry|CapabilityExploited)Event)/\\1  \\2/; s/, RuleId.*//'"

# Newest running pod, so a pod still terminating after a restart is never picked.
pod() {
    kubectl get pods -l app=imageservice --field-selector=status.phase=Running \
        --sort-by=.metadata.creationTimestamp -o name | tail -n1
}

in_pod() {
    kubectl exec "$(pod)" -c imageservice -- sh -c "$1"
}

# Port-forward to the pod (not the service, which can route to an old pod mid-rollout).
start_forward() {
    kubectl port-forward "$(pod)" "$PORT:80" >/dev/null 2>&1 &
    PF=$!
    trap 'kill $PF 2>/dev/null' EXIT
    curl -s --retry 15 --retry-all-errors --retry-delay 1 -o /dev/null "localhost:$PORT/"
}

import_tags() {
    printf '%b' "$1" | curl -s -w ' [HTTP %{http_code}]\n' -X POST "localhost:$PORT/importtags" --data-binary @-
}

case "$1" in
restart)
    kubectl delete pods -l app=imageservice --field-selector=status.phase=Failed --ignore-not-found
    kubectl rollout restart deploy/cargocats-imageservice
    kubectl rollout status deploy/cargocats-imageservice --timeout=180s
    echo "Run './dotnet-shield-demo.sh warm' next. The first YamlDotNet call after a restart is never shielded."
    ;;
warm)
    start_forward
    echo "Harmless tags import (normal usage, reports CVE exposure):"
    import_tags 'cat: whiskers\ncolor: orange\n'
    echo "Waiting up to 90s for the agent to load the $CVE shield..."
    in_pod "for i in \$(seq 1 45); do grep -q \"$LOADED\" $LOGS/*Sensors*.log 2>/dev/null && break; sleep 2; done
        if ! grep -q \"$LOADED\" $LOGS/*Sensors*.log 2>/dev/null; then
            echo 'Shield not loaded yet. Rerun warm. If it never loads, check that CVE Shield is enabled for your org.'
            exit 0
        fi
        echo 'Shield loaded for YamlDotNet. Mode the agent holds:'
        $SHIELD_FIELDS"
    ;;
exploit)
    start_forward
    in_pod "rm -f /tmp/pwned"
    echo "Sending $CVE payload: !<!ThumbnailHook,imageservice> with Command: touch /tmp/pwned"
    import_tags '!<!ThumbnailHook,imageservice>\nCommand: touch /tmp/pwned\n'
    if in_pod "test -f /tmp/pwned" 2>/dev/null; then
        echo "EXPLOITED: /tmp/pwned was created (shield in MONITOR, or Contrast off). Run 'clean' before the next try."
    else
        echo "BLOCKED: /tmp/pwned was not created. Run 'logs' for the agent evidence."
    fi
    ;;
logs)
    echo "== Agent version"
    in_pod "grep -h -m1 'Contrast Sensor Version' $LOGS/*Sensors*.log | sed -E 's/.*(Contrast Sensor Version)/\\1/'"
    echo "== $CVE shield loaded (mode, max behavior, denied capability)"
    in_pod "grep -h \"$LOADED\" $LOGS/*Sensors*.log | tail -n1 | sed -E 's/^([0-9-]+ [0-9:.]+).*(CVE .* matched library [^ ]+).*/\\1  \\2/'
        $SHIELD_FIELDS"
    echo "== Entry events (vulnerable method reached)"
    in_pod "grep -h \"'Entry' Event.*$CVE\" $LOGS/*Sensors*.log | tail -n5 | $EVENT_LINE | grep . || echo '$NEEDS_DEBUG'"
    echo "== Capability events (process start attempted in the CVE's scope)"
    in_pod "grep -h \"'Capability' Event.*$CVE\" $LOGS/*Sensors*.log | tail -n5 | $EVENT_LINE | grep . || echo '$NEEDS_DEBUG'"
    echo "== Blocks (from the app log)"
    kubectl logs "$(pod)" -c imageservice | grep "ShieldAttackBlockedException.*$CVE" | sed -E 's/^ *---> //' | tail -n5 \
        | grep . || echo "(none yet, the agent was not in BLOCK or exploit has not run)"
    ;;
clean)
    in_pod "rm -f /tmp/pwned"
    echo "Removed /tmp/pwned"
    ;;
*)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
