#!/usr/bin/env bash
set -euo pipefail

ticket_file="TICKETS.md"
repo=""
dry_run=true
create_labels=true
state_filter="all"

usage() {
  cat <<'USAGE'
Usage: scripts/create_github_issues_from_tickets.sh [options]

Create GitHub issues from ticket sections in TICKETS.md.

Options:
  --yes                 Create issues. Without this, the script only previews.
  --dry-run             Preview issues without creating them. This is the default.
  --file PATH           Ticket markdown file. Default: TICKETS.md.
  --repo OWNER/REPO     GitHub repository. Default: current gh repository context.
  --no-create-labels    Do not create missing labels before creating issues.
  --state STATE         Duplicate-check issue state: open, closed, or all. Default: all.
  --help                Show this help.

Ticket format:
  The script expects sections like:

    ## TLSFZ-001 Add persistent run IDs
    Priority: High
    Area: Reporting/Dashboard
    Labels: `enhancement`, `dashboard`

    Problem:
    ...

Duplicate handling:
  The script skips a ticket when an existing issue title contains the ticket ID
  or exactly matches the ticket title in the selected state.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)
      dry_run=false
      ;;
    --dry-run)
      dry_run=true
      ;;
    --file)
      ticket_file="${2:-}"
      shift
      ;;
    --repo)
      repo="${2:-}"
      shift
      ;;
    --no-create-labels)
      create_labels=false
      ;;
    --state)
      state_filter="${2:-}"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ ! -f "$ticket_file" ]]; then
  echo "Ticket file not found: $ticket_file" >&2
  exit 1
fi

case "$state_filter" in
  open|closed|all) ;;
  *)
    echo "--state must be open, closed, or all" >&2
    exit 1
    ;;
esac

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required" >&2
  exit 1
fi

gh_args=()
if [[ -n "$repo" ]]; then
  gh_args+=(--repo "$repo")
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

awk -v outdir="$tmp_dir" '
  /^## TLSFZ-[0-9]+ / {
    if (section != "") {
      print section > (outdir "/" id ".md")
    }
    id = $2
    section = $0 "\n"
    next
  }
  section != "" {
    section = section $0 "\n"
  }
  END {
    if (section != "") {
      print section > (outdir "/" id ".md")
    }
  }
' "$ticket_file"

mapfile -t section_files < <(find "$tmp_dir" -maxdepth 1 -type f -name 'TLSFZ-*.md' | sort)
if [[ "${#section_files[@]}" -eq 0 ]]; then
  echo "No ticket sections found in $ticket_file" >&2
  exit 1
fi

existing_titles="$(gh issue list "${gh_args[@]}" --state "$state_filter" --limit 1000 \
  --json number,title \
  --template '{{range .}}{{.title}}{{"\n"}}{{end}}' 2>/dev/null || true)"

issue_exists() {
  local id="$1"
  local title="$2"
  local title_lower existing_lower
  title_lower="$(printf '%s' "$title" | tr '[:upper:]' '[:lower:]')"

  while IFS= read -r existing_title; do
    [[ -z "$existing_title" ]] && continue
    existing_lower="$(printf '%s' "$existing_title" | tr '[:upper:]' '[:lower:]')"
    if [[ "$existing_title" == *"$id"* || "$existing_lower" == "$title_lower" ]]; then
      return 0
    fi
  done <<< "$existing_titles"

  return 1
}

label_exists() {
  local label="$1"
  gh label list "${gh_args[@]}" --limit 1000 | awk -F '\t' '{print $1}' | grep -Fxq "$label"
}

label_color() {
  case "$1" in
    bug) printf 'd73a4a' ;;
    documentation) printf '0075ca' ;;
    enhancement) printf 'a2eeef' ;;
    security) printf 'ee0701' ;;
    performance|perfomance) printf 'fbca04' ;;
    code-quality|logging|refactor) printf '5319e7' ;;
    dashboard|reporting|export|history) printf '1d76db' ;;
    testing|integration) printf '0e8a16' ;;
    tls|analysis|rfc-suite|fuzzer-core|evidence|configuration|generator|stability) printf 'bfd4f2' ;;
    *) printf 'ededed' ;;
  esac
}

ensure_label() {
  local label="$1"
  if label_exists "$label"; then
    return
  fi

  if [[ "$dry_run" == "true" ]]; then
    echo "  would create missing label: $label"
    return
  fi

  if [[ "$create_labels" == "true" ]]; then
    gh label create "${gh_args[@]}" "$label" \
      --color "$(label_color "$label")" \
      --description "Imported from $ticket_file" >/dev/null
    echo "  created missing label: $label"
  else
    echo "Missing label '$label'. Re-run without --no-create-labels or create it manually." >&2
    exit 1
  fi
}

extract_labels() {
  local file="$1"
  sed -n 's/^Labels:[[:space:]]*//p' "$file" |
    tr ',' '\n' |
    sed -E 's/`//g; s/^[[:space:]]+//; s/[[:space:]]+$//' |
    sed '/^$/d'
}

created=0
skipped=0
planned=0

for section_file in "${section_files[@]}"; do
  first_line="$(sed -n '1p' "$section_file")"
  id="$(awk '{print $2}' <<<"$first_line")"
  title="${first_line#\#\# $id }"

  if [[ -z "$id" || -z "$title" ]]; then
    echo "Skipping malformed section: $section_file" >&2
    skipped=$((skipped + 1))
    continue
  fi

  if issue_exists "$id" "$title"; then
    echo "skip existing: $id $title"
    skipped=$((skipped + 1))
    continue
  fi

  mapfile -t labels < <(extract_labels "$section_file")
  label_csv=""
  for label in "${labels[@]}"; do
    ensure_label "$label"
    if [[ -z "$label_csv" ]]; then
      label_csv="$label"
    else
      label_csv="$label_csv,$label"
    fi
  done

  body_file="$tmp_dir/body-$id.md"
  {
    echo "<!-- Imported from $ticket_file: $id -->"
    echo
    echo "Ticket ID: \`$id\`"
    echo
    sed '1d' "$section_file"
  } > "$body_file"

  if [[ "$dry_run" == "true" ]]; then
    echo "would create: $id $title"
    if [[ -n "$label_csv" ]]; then
      echo "  labels: $label_csv"
    fi
    planned=$((planned + 1))
    continue
  fi

  create_args=("${gh_args[@]}" --title "$title" --body-file "$body_file")
  if [[ -n "$label_csv" ]]; then
    create_args+=(--label "$label_csv")
  fi
  url="$(gh issue create "${create_args[@]}")"
  echo "created: $id $url"
  created=$((created + 1))
done

if [[ "$dry_run" == "true" ]]; then
  echo "Dry run complete: planned=$planned skipped=$skipped"
else
  echo "Issue creation complete: created=$created skipped=$skipped"
fi
