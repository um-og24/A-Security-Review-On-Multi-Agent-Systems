#!/usr/bin/env bash
set -euo pipefail

# Git Bash friendly wrapper for the A2A Smart Home Lab
# Uses "docker compose" by default. To use legacy binary:
#   COMPOSE_BIN=docker-compose ./lab.sh publish

COMPOSE_BIN="${COMPOSE_BIN:-docker compose}"

CERTS_DIR="${CERTS_DIR:-certs}"
CERT_SCRIPT="${CERT_SCRIPT:-./create_lab_certs.sh}"

# Service groups (shortcuts)
GENUINE_SERVICES=("genuine-thermostat" "genuine-camera" "genuine-doorlock" "genuine-lighting")
PYTHON_SERVICES=("logger" "web-dashboard" "smart-home-hub" "attacker-relay" "llm-proxy" "piper-tts" "genuine-thermostat" "genuine-camera" "genuine-doorlock" "genuine-lighting")

usage() {
  cat <<'EOF'
Usage:
  ./lab.sh publish [--no-down] [--no-certs] [--force-certs]
  ./lab.sh up
  ./lab.sh down
  ./lab.sh build
  ./lab.sh restart [all|<service>|all-genuine]
  ./lab.sh bounce
  ./lab.sh logs [<service>]
  ./lab.sh ps
  ./lab.sh certs [--force]
  ./lab.sh clean-certs
  ./lab.sh --help

Commands:
  publish      Full update flow: down -v, optionally regen certs, up -d
  up           docker compose up -d
  down         docker compose down -v
  build        docker compose up -d --build
  restart      Restart a service, or a group (all, all-genuine), or all services
  bounce       Quick restart of all Python services (logger, dashboard, hub, attacker, llm-proxy, piper-tts, all genuine agents)
  logs         Tail logs (all services by default, or a specific service)
  ps           Show container status
  certs        Generate certs only (no compose)
  clean-certs  Remove certs directory

Flags (publish):
  --no-down     Skip docker compose down -v (faster for quick updates)
  --no-certs    Skip cert regeneration
  --force-certs Force cert regeneration (deletes certs dir first)

Flags (certs):
  --force       Force regeneration (deletes certs dir first)

Examples:
  ./lab.sh publish
  ./lab.sh publish --no-down --no-certs
  ./lab.sh publish --force-certs
  ./lab.sh restart web-dashboard
  ./lab.sh restart smart-home-hub
  ./lab.sh restart all-genuine
  ./lab.sh bounce
  ./lab.sh logs web-dashboard
  ./lab.sh logs piper-tts

Notes: which service to restart after edits
  index.html, web_dashboard.py                  -> ./lab.sh restart web-dashboard
  smart_home_hub.py, llm_selector.py            -> ./lab.sh restart smart-home-hub
  attacker_relay.py                             -> ./lab.sh restart attacker-relay
  server_genuine.py                             -> ./lab.sh restart all-genuine
  logger_service.py, logger.py                  -> ./lab.sh restart logger
  llm_proxy.py, llm_manager.py                 -> ./lab.sh restart llm-proxy
  tts_service.py                                -> ./lab.sh restart piper-tts
  log_client.py, config_manager.py, a2a_models.py -> ./lab.sh bounce
EOF
}

need_cert_script() {
  if [ ! -f "$CERT_SCRIPT" ]; then
    echo "[ERR] Missing $CERT_SCRIPT"
    exit 1
  fi
  chmod +x "$CERT_SCRIPT"
}

gen_certs_force() {
  need_cert_script
  rm -rf "$CERTS_DIR"
  "$CERT_SCRIPT"
}

cmd="${1:-publish}"
if [ "$cmd" = "--help" ] || [ "$cmd" = "-h" ]; then
  usage
  exit 0
fi
shift || true

PUBLISH_NO_DOWN=0
PUBLISH_DO_CERTS=1
PUBLISH_FORCE_CERTS=0
CERTS_FORCE=0

# Parse flags (applies to selected command)
while [ $# -gt 0 ]; do
  case "$1" in
    --no-down)
      PUBLISH_NO_DOWN=1
      shift
      ;;
    --no-certs)
      PUBLISH_DO_CERTS=0
      shift
      ;;
    --force-certs)
      PUBLISH_DO_CERTS=1
      PUBLISH_FORCE_CERTS=1
      shift
      ;;
    --force)
      CERTS_FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      # stop parsing flags when we hit a non-flag argument for commands like restart/logs
      break
      ;;
  esac
done

restart_target() {
  local target="${1:-all}"

  if [ "$target" = "all" ]; then
    $COMPOSE_BIN restart
    return
  fi

  if [ "$target" = "all-genuine" ]; then
    $COMPOSE_BIN restart "${GENUINE_SERVICES[@]}"
    return
  fi

  $COMPOSE_BIN restart "$target"
}

case "$cmd" in
  publish)
    if [ "$PUBLISH_NO_DOWN" -eq 0 ]; then
      $COMPOSE_BIN down -v
    else
      echo "[compose] Skipping down -v (--no-down)"
    fi

    if [ "$PUBLISH_DO_CERTS" -eq 1 ]; then
      if [ "$PUBLISH_FORCE_CERTS" -eq 1 ]; then
        gen_certs_force
      else
        if [ ! -f "$CERTS_DIR/lab-ca.crt" ]; then
          gen_certs_force
        else
          echo "[certs] Present, skipping (use --force-certs to regenerate)"
        fi
      fi
    else
      echo "[certs] Skipped (--no-certs)"
    fi

    $COMPOSE_BIN up -d
    ;;
  up)
    $COMPOSE_BIN up -d
    ;;
  down)
    $COMPOSE_BIN down -v
    ;;
  build)
    $COMPOSE_BIN up -d --build
    ;;
  restart)
    restart_target "${1:-all}"
    ;;
  bounce)
    # Quick restart of python services to pick up bind-mounted changes
    $COMPOSE_BIN restart "${PYTHON_SERVICES[@]}"
    ;;
  logs)
    if [ $# -gt 0 ]; then
      $COMPOSE_BIN logs -f --tail=200 "$1"
    else
      $COMPOSE_BIN logs -f --tail=200
    fi
    ;;
  ps)
    $COMPOSE_BIN ps
    ;;
  certs)
    if [ "$CERTS_FORCE" -eq 1 ]; then
      gen_certs_force
    else
      need_cert_script
      if [ -f "$CERTS_DIR/lab-ca.crt" ]; then
        echo "[certs] Present: $CERTS_DIR/lab-ca.crt"
        echo "        Use: ./lab.sh certs --force"
        exit 0
      fi
      "$CERT_SCRIPT"
    fi
    ;;
  clean-certs)
    rm -rf "$CERTS_DIR"
    echo "[OK] Removed $CERTS_DIR/"
    ;;
  --help|-h)
    usage
    ;;
  *)
    echo "[ERR] Unknown command: $cmd"
    echo ""
    usage
    exit 1
    ;;
esac
