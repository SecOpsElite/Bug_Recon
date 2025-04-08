#!/bin/bash
# ================================================
# Advanced GitHub Recon Script
# Author: The Cybersecurity Professor (Enhanced by AI)
# Version: 3.0
# Purpose: Automates GitHub reconnaissance for bug bounty hunting.
# Features: Command-line args, modular functions, dorking, optional full clones,
#           secrets detection (Gitleaks, TruffleHog), JS endpoint extraction,
#           subdomain enumeration (code + subfinder), live host probing (httpx),
#           URL discovery (gau), screenshotting (gowitness), vuln scanning (Nuclei),
#           rate limit checks, optional cleanup, summary report.
# ================================================

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Script Information ---
SCRIPT_NAME=$(basename "$0")
SCRIPT_VERSION="3.0"

# --- Default Settings ---
DEFAULT_OUT_DIR_PREFIX="./github-recon-"
GITHUB_DORKS=(
    '"api_key"' '"apikey"' '"secret_key"' '"secretkey"' '"password"'
    '"passwd"' '"credentials"' '"access_token"' '"accesstoken"'
    '"client_secret"' '"clientsecret"' 'filename:.env' 'filename:.npmrc'
    'filename:.dockercfg' 'filename:config.js' 'filename:settings.py'
    'extension:pem' 'extension:ppk' 'extension:key' 'extension:json api'
    'extension:yaml' 'internal' 'staging' 'deploy' 'backup' 'database'
    'admin' 'jenkins' 'BEGIN RSA PRIVATE KEY' 'BEGIN PGP PRIVATE KEY BLOCK'
    'BEGIN OPENSSH PRIVATE KEY'
)
# Nuclei templates - adjust as needed
NUCLEI_TEMPLATES="technologies,cves,misconfiguration,vulnerabilities"
NUCLEI_EXCLUSIONS="info,misc" # Tags to exclude

# --- Global Variables ---
declare -a TARGET_DOMAINS=() # Array to hold specified domains
GH_TARGET=""
OUT_DIR=""
LOG_FILE=""
SUMMARY_REPORT_FILE=""
FULL_CLONE=false
CLEANUP_REPOS=false
# Flags to control execution flow
RUN_DORKING=true
RUN_CLONING=true
RUN_SECRETS_SCAN=true
RUN_ENDPOINT_EXTRACTION=true
RUN_SUBDOMAIN_EXTRACTION=true
RUN_SUBFINDER=true
RUN_HTTPX=true
RUN_GAU=true
RUN_GOWITNESS=true
RUN_NUCLEI=true

# --- Utility Functions ---

# Log messages with timestamp and level
log_msg() {
    local level="$1"
    local color="$2"
    local message="$3"
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] ${color}[${level}] ${message}${NC}" | tee -a "$LOG_FILE"
}

info() { log_msg "INFO" "$BLUE" "$1"; }
warn() { log_msg "WARN" "$YELLOW" "$1"; }
error() { log_msg "ERROR" "$RED" "$1"; }
success() { log_msg "SUCCESS" "$GREEN" "$1"; }
step() { echo; log_msg "STEP" "$GREEN" "$1"; } # Add newline before step

# Check if a command-line tool is available
check_tool() {
    local tool_name="$1"
    local required="$2" # Optional: 'required' or 'optional'
    if ! command -v "$tool_name" &> /dev/null; then
        if [[ "$required" == "required" ]]; then
            error "'$tool_name' command not found, but it is required. Please install it. Exiting."
            exit 1
        else
            warn "'$tool_name' command not found. Some functionality relying on it will be skipped."
            return 1 # Indicate tool not found
        fi
    fi
    # info "'$tool_name' found." # Optional: uncomment for verbose checks
    return 0 # Indicate tool found
}

# Check GitHub CLI authentication
check_gh_auth() {
    info "Checking GitHub CLI authentication..."
    if ! gh auth status &> /dev/null; then
        error "GitHub CLI 'gh' is not authenticated. Please run 'gh auth login' and try again. Exiting."
        exit 1
    fi
    success "GitHub CLI is authenticated."
    # Check for GITHUB_TOKEN env var
    if [[ -n "$GITHUB_TOKEN" ]]; then
        info "Using GITHUB_TOKEN environment variable for GitHub API authentication."
    else
        warn "GITHUB_TOKEN environment variable not set. You might encounter stricter rate limits."
    fi
}

# Check GitHub API rate limits
check_rate_limit() {
    info "Checking GitHub API rate limit..."
    local limit_info
    limit_info=$(gh api rate_limit --jq '.resources.core')
    if [[ $? -ne 0 ]]; then
        warn "Could not check rate limit. Proceeding with caution."
        return
    fi
    local remaining=$(echo "$limit_info" | jq -r '.remaining')
    local limit=$(echo "$limit_info" | jq -r '.limit')
    local reset_timestamp=$(echo "$limit_info" | jq -r '.reset')
    local reset_time=$(date -d @"$reset_timestamp" '+%Y-%m-%d %H:%M:%S')

    info "API Rate Limit: $remaining/$limit remaining. Resets at $reset_time."
    if [[ "$remaining" -lt 50 ]]; then # Adjust threshold as needed
        warn "Low API rate limit remaining ($remaining). Consider waiting or using a GITHUB_TOKEN."
    fi
}

# --- Core Recon Functions ---

# Step 1: GitHub Dorking
run_github_dorking() {
    step "1: Running GitHub Code Search Dorking..."
    local dork_output_dir="$OUT_DIR/dorking"
    local dork_output_file="$dork_output_dir/code-search-results.md"
    mkdir -p "$dork_output_dir"

    info "Searching for common secrets patterns using 'gh search code'..."
    echo "# GitHub Dorking Results for $GH_TARGET" > "$dork_output_file"
    echo "**Timestamp:** $(date)" >> "$dork_output_file"
    echo >> "$dork_output_file" # Newline

    local found_count=0
    for dork in "${GITHUB_DORKS[@]}"; do
        info "Searching for: org:$GH_TARGET $dork"
        local search_results
        # Use process substitution to capture output and check exit status
        if ! search_results=$(gh search code "org:$GH_TARGET $dork" --limit 10 --json url,path,repository 2>&1); then
            warn "'gh search code' command failed for dork: $dork. Error: $search_results. Skipping."
            echo "## Dork: \`$dork\`" >> "$dork_output_file"
            echo "**FAILED**: Error during search." >> "$dork_output_file"
            echo '---' >> "$dork_output_file"
            continue
        fi

        # Check if results are empty (jq returns empty or null for no results)
        if [[ -z "$search_results" || "$search_results" == "null" || "$search_results" == "[]" ]]; then
             info "No results found for dork: $dork"
             echo "## Dork: \`$dork\`" >> "$dork_output_file"
             echo "_No results found._" >> "$dork_output_file"
        else
            info "Results found for dork: $dork"
            echo "## Dork: \`$dork\`" >> "$dork_output_file"
            echo '```json' >> "$dork_output_file"
            echo "$search_results" >> "$dork_output_file"
            echo '```' >> "$dork_output_file"
            found_count=$((found_count + $(echo "$search_results" | jq length)))
        fi
        echo '---' >> "$dork_output_file"
        sleep 2 # Be nice to the API
    done

    success "Dorking complete. Found potential items in $found_count results. Saved to $dork_output_file"
    echo "- [GitHub Dorking](#github-dorking): Found potential items in $found_count results ([details]($dork_output_file))" >> "$SUMMARY_REPORT_FILE"
}

# Step 2: Clone Repositories
run_repo_cloning() {
    step "2: Cloning Public Repositories..."
    local repos_list_file="$OUT_DIR/repos-list.txt"
    local repos_dir="$OUT_DIR/repos"
    mkdir -p "$repos_dir"

    info "Fetching list of public repositories for '$GH_TARGET'..."
    if ! gh repo list "$GH_TARGET" --limit 1000 --source --json name,url --jq '.[].url' > "$repos_list_file"; then
        error "Failed to fetch repository list for '$GH_TARGET'. Check target name and permissions. Skipping cloning and local analysis."
        # Set flags to skip dependent steps
        RUN_SECRETS_SCAN=false
        RUN_ENDPOINT_EXTRACTION=false
        RUN_SUBDOMAIN_EXTRACTION=false
        return 1
    fi

    local repo_count=$(wc -l < "$repos_list_file")
    if [[ "$repo_count" -eq 0 ]]; then
        warn "No public repositories found for '$GH_TARGET'. Skipping cloning and local analysis."
        RUN_SECRETS_SCAN=false
        RUN_ENDPOINT_EXTRACTION=false
        RUN_SUBDOMAIN_EXTRACTION=false
        return 1
    fi

    info "Found $repo_count public repositories. Cloning into '$repos_dir' directory..."
    local clone_opts="--quiet"
    if [[ "$FULL_CLONE" = false ]]; then
        clone_opts="$clone_opts --depth=1"
        info "Using shallow clones (--depth=1). For full history analysis, use --full-clone."
    else
        info "Using full clones. This may take significantly more time and disk space."
    fi

    local CLONE_COUNT=0
    local FAIL_COUNT=0
    while IFS= read -r url; do
        local repo_name=$(basename "$url" .git)
        info "Cloning $repo_name..."
        if ! git clone $clone_opts "$url" "$repos_dir/$repo_name"; then
            warn "Failed to clone $url. Skipping."
            ((FAIL_COUNT++))
        else
            ((CLONE_COUNT++))
        fi
    done < "$repos_list_file"

    success "Cloning complete. Successfully cloned $CLONE_COUNT repositories. Failed to clone $FAIL_COUNT."
    echo "- [Repository Cloning](#repository-cloning): Cloned $CLONE_COUNT repositories." >> "$SUMMARY_REPORT_FILE"
    [[ "$FAIL_COUNT" -gt 0 ]] && echo "  - Failed to clone $FAIL_COUNT repositories." >> "$SUMMARY_REPORT_FILE"

    # Check if any repos were cloned before enabling subsequent steps
    if [[ "$CLONE_COUNT" -eq 0 ]]; then
        warn "No repositories were successfully cloned. Skipping local analysis steps."
        RUN_SECRETS_SCAN=false
        RUN_ENDPOINT_EXTRACTION=false
        RUN_SUBDOMAIN_EXTRACTION=false
        return 1
    fi
    return 0
}

# Step 3: Secrets Scanning (Gitleaks & TruffleHog)
run_secrets_scanning() {
    step "3: Running Secrets Scanning..."
    local repos_dir="$OUT_DIR/repos"
    local gitleaks_dir="$OUT_DIR/secrets/gitleaks"
    local trufflehog_dir="$OUT_DIR/secrets/trufflehog"
    mkdir -p "$gitleaks_dir" "$trufflehog_dir"

    local gitleaks_found=0
    local trufflehog_found=0

    # Run Gitleaks
    if check_tool "gitleaks" "optional"; then
        info "Running Gitleaks scan..."
        for repo_path in "$repos_dir"/*; do
            if [ -d "$repo_path/.git" ]; then
                local repo_name=$(basename "$repo_path")
                local report_file="$gitleaks_dir/${repo_name}-report.json"
                info "Scanning $repo_name with Gitleaks..."
                gitleaks detect -s "$repo_path" --report-path "$report_file" --report-format json --no-banner -v
                # Check if report file is non-empty (basic check for findings)
                if [[ -s "$report_file" ]]; then
                    local count=$(jq length "$report_file")
                    if [[ "$count" -gt 0 ]]; then
                         warn "Gitleaks found $count potential secrets in $repo_name."
                         gitleaks_found=$((gitleaks_found + count))
                    fi
                fi
            fi
        done
        success "Gitleaks scan complete. Found $gitleaks_found potential secrets."
    else
        warn "Gitleaks not found, skipping Gitleaks scan."
    fi

    # Run TruffleHog
    if check_tool "trufflehog" "optional"; then
        info "Running TruffleHog scan (can be slow)..."
        for repo_path in "$repos_dir"/*; do
            if [ -d "$repo_path" ]; then
                local repo_name=$(basename "$repo_path")
                local report_file="$trufflehog_dir/${repo_name}-report.json"
                info "Scanning $repo_path with TruffleHog..."
                trufflehog filesystem --directory "$repo_path" --json > "$report_file"
                # Check if report file is non-empty and not just '[]'
                 if [[ -s "$report_file" && "$(jq 'length > 0' "$report_file")" == "true" ]]; then
                    local count=$(jq length "$report_file")
                    warn "TruffleHog found $count potential secrets in $repo_name."
                    trufflehog_found=$((trufflehog_found + count))
                else
                    # Clean up empty report files
                    rm -f "$report_file"
                fi
            fi
        done
        success "TruffleHog scan complete. Found $trufflehog_found potential secrets."
    else
        warn "TruffleHog not found, skipping TruffleHog scan."
    fi

    echo "- [Secrets Scanning](#secrets-scanning):" >> "$SUMMARY_REPORT_FILE"
    echo "  - Gitleaks: Found $gitleaks_found potential secrets ([details]($gitleaks_dir/))" >> "$SUMMARY_REPORT_FILE"
    echo "  - TruffleHog: Found $trufflehog_found potential secrets ([details]($trufflehog_dir/))" >> "$SUMMARY_REPORT_FILE"
}

# Step 4: Extract JS Endpoints
run_endpoint_extraction() {
    step "4: Extracting Potential Endpoints from JS Files..."
    local repos_dir="$OUT_DIR/repos"
    local endpoints_dir="$OUT_DIR/endpoints"
    local js_endpoints_file="$endpoints_dir/js_endpoints_sorted.txt"
    mkdir -p "$endpoints_dir"

    info "Searching for URL patterns and paths in *.js files..."
    find "$repos_dir/" -name "*.js" -type f -exec cat {} + 2>/dev/null | \
        grep -Eoi '"(https?://|/)[a-zA-Z0-9./?=_%~&+-]*"' | \
        sed -e 's/^"//' -e 's/"$//' | \
        sort -u > "$js_endpoints_file"

    local count=$(wc -l < "$js_endpoints_file")
    success "Extracted $count potential unique JS endpoints to $js_endpoints_file"
    echo "- [JS Endpoint Extraction](#js-endpoint-extraction): Found $count potential endpoints ([details]($js_endpoints_file))" >> "$SUMMARY_REPORT_FILE"
}

# Step 5: Extract Subdomains from Code
run_subdomain_extraction() {
    step "5: Extracting Potential Subdomains/Domains from Code..."
    local repos_dir="$OUT_DIR/repos"
    local subdomains_dir="$OUT_DIR/subdomains"
    local code_subdomains_file="$subdomains_dir/subdomains_from_code.txt"
    mkdir -p "$subdomains_dir"

    info "Using grep to find potential FQDN patterns in cloned code..."
    grep -Eohr "[a-zA-Z0-9]+([.-][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}" "$repos_dir/" | \
        sort -u > "$code_subdomains_file"

    local count=$(wc -l < "$code_subdomains_file")
    success "Extracted $count potential unique domains/subdomains from code to $code_subdomains_file"
    warn "Review this file manually as it may contain non-target or public domains."
    echo "- [Subdomain Extraction (Code)](#subdomain-extraction-code): Found $count potential domains ([details]($code_subdomains_file))" >> "$SUMMARY_REPORT_FILE"
}

# Step 6: Subdomain Enumeration with Subfinder
run_subfinder_enum() {
    step "6: Running Subdomain Enumeration (Subfinder)..."
    if ! check_tool "subfinder" "optional"; then
        warn "Subfinder not found. Skipping Subfinder enumeration."
        echo "- [Subdomain Enumeration (Subfinder)](#subdomain-enumeration-subfinder): Skipped (subfinder not found)" >> "$SUMMARY_REPORT_FILE"
        return 1
    fi

    if [[ ${#TARGET_DOMAINS[@]} -eq 0 ]]; then
        warn "No target domains specified with --domain flag. Skipping Subfinder enumeration."
        echo "- [Subdomain Enumeration (Subfinder)](#subdomain-enumeration-subfinder): Skipped (no --domain specified)" >> "$SUMMARY_REPORT_FILE"
        return 1
    fi

    local subdomains_dir="$OUT_DIR/subdomains"
    local subfinder_output_file="$subdomains_dir/subdomains_from_subfinder.txt"
    mkdir -p "$subdomains_dir"

    info "Running subfinder on specified domains: ${TARGET_DOMAINS[*]}"
    # Create temporary file with domains for subfinder -dL flag
    local domain_list_file=$(mktemp)
    printf "%s\n" "${TARGET_DOMAINS[@]}" > "$domain_list_file"

    subfinder -dL "$domain_list_file" -o "$subfinder_output_file" -silent
    rm "$domain_list_file" # Clean up temp file

    if [[ ! -f "$subfinder_output_file" ]]; then
        warn "Subfinder did not produce an output file."
        touch "$subfinder_output_file" # Create empty file
    fi

    local count=$(wc -l < "$subfinder_output_file")
    success "Subfinder enumeration complete. Found $count subdomains. Saved to $subfinder_output_file"
    echo "- [Subdomain Enumeration (Subfinder)](#subdomain-enumeration-subfinder): Found $count subdomains ([details]($subfinder_output_file))" >> "$SUMMARY_REPORT_FILE"
}

# Step 7: Combine and Probe Live Hosts (httpx)
run_httpx_probing() {
    step "7: Probing for Live Hosts (httpx)..."
     if ! check_tool "httpx" "optional"; then
        warn "httpx not found. Skipping live host probing."
        echo "- [Live Host Probing (httpx)](#live-host-probing-httpx): Skipped (httpx not found)" >> "$SUMMARY_REPORT_FILE"
        return 1
    fi

    local subdomains_dir="$OUT_DIR/subdomains"
    local httpx_dir="$OUT_DIR/httpx-results"
    local combined_subdomains_file="$subdomains_dir/subdomains_combined_unique.txt"
    local live_hosts_file="$httpx_dir/live_hosts_httpx.txt"
    mkdir -p "$httpx_dir"

    info "Combining unique subdomains from code and subfinder..."
    cat "$subdomains_dir/subdomains_from_code.txt" "$subdomains_dir/subdomains_from_subfinder.txt" 2>/dev/null | \
        sort -u > "$combined_subdomains_file"

    local combined_count=$(wc -l < "$combined_subdomains_file")
    info "Total unique potential domains/subdomains to probe: $combined_count"

    if [[ ! -s "$combined_subdomains_file" ]]; then
        warn "No domains/subdomains found to probe. Skipping httpx."
        echo "- [Live Host Probing (httpx)](#live-host-probing-httpx): Skipped (no input domains)" >> "$SUMMARY_REPORT_FILE"
        return 1
    fi

    info "Running httpx on combined list..."
    httpx -silent -l "$combined_subdomains_file" -o "$live_hosts_file" \
          -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
          -threads 50 -status-code -title -tech-detect

    if [[ ! -f "$live_hosts_file" ]]; then
        warn "httpx did not produce an output file."
        touch "$live_hosts_file" # Create empty file
    fi

    local live_count=$(wc -l < "$live_hosts_file")
    success "httpx probing complete. Found $live_count potentially live hosts. Saved to $live_hosts_file"
    echo "- [Live Host Probing (httpx)](#live-host-probing-httpx): Found $live_count live hosts ([details]($live_hosts_file))" >> "$SUMMARY_REPORT_FILE"
}

# Step 8: Discover URLs (gau)
run_gau_discovery() {
    step "8: Discovering Known URLs (gau)..."
    if ! check_tool "gau" "optional"; then
        warn "gau not found. Skipping URL discovery."
        echo "- https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a(#url-discovery-gau): Skipped (gau not found)" >> "$SUMMARY_REPORT_FILE"
        return 1
    fi

    local httpx_dir="$OUT_DIR/httpx-results"
    local endpoints_dir="$OUT_DIR/endpoints"
    local live_hosts_file="$httpx_dir/live_hosts_httpx.txt" # Use httpx output containing URLs
    local gau_output_file="$endpoints_dir/urls_from_gau.txt"
    mkdir -p "$endpoints_dir"

    # Extract just the URLs (first column) from httpx output if it exists and has content
    if [[ -s "$live_hosts_file" ]]; then
        # Use awk to get the first field which should be the URL in httpx output
        awk '{print $1}' "$live_hosts_file" > "$endpoints_dir/live_urls_for_gau.tmp"

        if [[ -s "$endpoints_dir/live_urls_for_gau.tmp" ]]; then
             info "Running gau on live hosts found by httpx..."
             cat "$endpoints_dir/live_urls_for_gau.tmp" | gau --threads 5 --subs > "$gau_output_file"
             rm "$endpoints_dir/live_urls_for_gau.tmp" # Clean up temp file
        else
            warn "Could not extract URLs from httpx output. Skipping gau."
            rm "$endpoints_dir/live_urls_for_gau.tmp"
            touch "$gau_output_file" # Create empty file
        fi
    else
        warn "No live hosts file ($live_hosts_file) found or empty. Skipping gau."
        touch "$gau_output_file" # Create empty file
    fi

    local count=$(wc -l < "$gau_output_file")
    success "gau URL discovery complete. Found $count URLs. Saved to $gau_output_file"
    echo "- https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a(#url-discovery-gau): Found $count URLs ([details]($gau_output_file))" >> "$SUMMARY_REPORT_FILE"
}

# Step 9: Screenshot Live Hosts (gowitness)
run_gowitness_screenshots() {
    step "9: Screenshotting Live Web Applications (gowitness)..."
     if ! check_tool "gowitness" "optional"; then
        warn "gowitness not found. Skipping screenshotting."
        echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Skipped (gowitness not found)" >> "$SUMMARY_REPORT_FILE"
        return 1
    fi

    local httpx_dir="$OUT_DIR/httpx-results"
    local gowitness_dir="$OUT_DIR/gowitness-results"
    local live_hosts_file="$httpx_dir/live_hosts_httpx.txt" # Use httpx output
    mkdir -p "$gowitness_dir"

    if [[ ! -s "$live_hosts_file" ]]; then
        warn "No live hosts file ($live_hosts_file) found or empty. Skipping gowitness."
        echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Skipped (no input hosts)" >> "$SUMMARY_REPORT_FILE"
        return 1
    fi

    info "Running gowitness on live hosts..."
    # Extract URLs for gowitness
    awk '{print $1}' "$live_hosts_file" > "$gowitness_dir/urls_for_gowitness.tmp"

    if [[ -s "$gowitness_dir/urls_for_gowitness.tmp" ]]; then
        # Run gowitness, saving db and screenshots in the output dir
        # Use --disable-db if you only want screenshots
        gowitness file -f "$gowitness_dir/urls_for_gowitness.tmp" \
            --destination "$gowitness_dir/screenshots/" \
            --db "$gowitness_dir/gowitness.sqlite3" \
            --threads 5
        rm "$gowitness_dir/urls_for_gowitness.tmp"
        success "gowitness screenshotting complete. Results in $gowitness_dir"
        echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Completed ([details]($gowitness_dir/))" >> "$SUMMARY_REPORT_FILE"
    else
        warn "Could not extract URLs for gowitness. Skipping."
        rm "$gowitness_dir/urls_for_gowitness.tmp"
        echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Skipped (could not extract URLs)" >> "$SUMMARY_REPORT_FILE"
    fi
}

# Step 10: Vulnerability Scanning (Nuclei)
run_nuclei_scan() {
    step "10: Running Vulnerability Scanning (Nuclei)..."
    if ! check_tool "nuclei" "optional"; then
        warn "Nuclei not found. Skipping vulnerability scan."
        echo "- [Vulnerability Scanning (Nuclei)](#vulnerability-scanning-nuclei): Skipped (nuclei not found)" >> "$SUMMARY_REPORT_FILE"
        return 1
    fi

    local httpx_dir="$OUT_DIR/httpx-results"
    local nuclei_dir="$OUT_DIR/nuclei-results"
    local live_hosts_file="$httpx_dir/live_hosts_httpx.txt" # Use httpx output
    local nuclei_report_file="$nuclei_dir/nuclei_scan_report.txt"
    mkdir -p "$nuclei_dir"

    if [[ ! -s "$live_hosts_file" ]]; then
        warn "No live hosts file ($live_hosts_file) found or empty. Skipping Nuclei scan."
        echo "- [Vulnerability Scanning (Nuclei)](#vulnerability-scanning-nuclei): Skipped (no input hosts)" >> "$SUMMARY_REPORT_FILE"
        return 1
    fi

    info "Running Nuclei on live hosts using templates: $NUCLEI_TEMPLATES (excluding: $NUCLEI_EXCLUSIONS)..."
    nuclei -l "$live_hosts_file" \
           -t "$NUCLEI_TEMPLATES" \
           -etags "$NUCLEI_EXCLUSIONS" \
           -stats -silent -o "$nuclei_report_file" \
           -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

    local finding_count=0
    if [[ -f "$nuclei_report_file" ]]; then
        finding_count=$(wc -l < "$nuclei_report_file")
    fi

    success "Nuclei scan complete. Found $finding_count potential findings. Report saved to $nuclei_report_file"
    echo "- [Vulnerability Scanning (Nuclei)](#vulnerability-scanning-nuclei): Found $finding_count potential findings ([details]($nuclei_report_file))" >> "$SUMMARY_REPORT_FILE"
}

# Step 11: Cleanup
run_cleanup() {
    step "11: Cleaning up cloned repositories..."
    local repos_dir="$OUT_DIR/repos"
    if [ -d "$repos_dir" ]; then
        info "Removing cloned repositories directory: $repos_dir"
        rm -rf "$repos_dir"
        success "Cleanup complete."
        echo "- [Cleanup](#cleanup): Removed cloned repositories directory." >> "$SUMMARY_REPORT_FILE"
    else
        info "Cloned repositories directory not found ($repos_dir). Nothing to clean up."
         echo "- [Cleanup](#cleanup): No repositories directory found to remove." >> "$SUMMARY_REPORT_FILE"
    fi
}

# --- Argument Parsing ---
usage() {
    echo "Usage: $SCRIPT_NAME -t <target> [-o <out_dir>] [-d <domain>] [--full-clone] [--cleanup] [skip_flags...]"
    echo ""
    echo "Required:"
    echo "  -t, --target <username/org>  GitHub username or organization to scan."
    echo ""
    echo "Options:"
    echo "  -o, --output <dir>           Output directory (default: ${DEFAULT_OUT_DIR_PREFIX}<target>)."
    echo "  -d, --domain <domain>        Target domain for focused subdomain enumeration (can be used multiple times)."
    echo "      --full-clone             Perform full git clones (default: shallow --depth=1)."
    echo "      --cleanup                Remove cloned 'repos/' directory after script completion."
    echo "      --skip-dorking           Skip GitHub code search dorking."
    echo "      --skip-cloning           Skip cloning repositories (also skips local analysis steps)."
    echo "      --skip-secrets           Skip Gitleaks and TruffleHog scans."
    echo "      --skip-endpoints         Skip JS endpoint extraction."
    echo "      --skip-subdomains-code   Skip subdomain extraction from code."
    echo "      --skip-subfinder         Skip subdomain enumeration using Subfinder."
    echo "      --skip-httpx             Skip live host probing using httpx."
    echo "      --skip-gau               Skip URL discovery using gau."
    echo "      --skip-gowitness         Skip screenshotting using gowitness."
    echo "      --skip-nuclei            Skip vulnerability scanning using Nuclei."
    echo "  -h, --help                   Show this help message."
    echo "  -v, --version                Show script version."
    echo ""
    echo "Example:"
    echo "  $SCRIPT_NAME -t MyOrg -d myorg.com -d myorg-prod.com -o ./myorg-recon --full-clone"
    echo "  $SCRIPT_NAME -t MyUser --skip-cloning --skip-secrets"
    exit 1
}

# Use getopt for robust argument parsing
TEMP=$(getopt -o t:o:d:hv --long target:,output:,domain:,full-clone,cleanup,skip-dorking,skip-cloning,skip-secrets,skip-endpoints,skip-subdomains-code,skip-subfinder,skip-httpx,skip-gau,skip-gowitness,skip-nuclei,help,version -n "$SCRIPT_NAME" -- "$@")

if [ $? != 0 ]; then error "Terminating... Invalid arguments." >&2; usage; fi

# Note the quotes around '$TEMP': they are essential!
eval set -- "$TEMP"
unset TEMP

while true; do
    case "$1" in
        '-t'|'--target') GH_TARGET="$2"; shift 2 ;;
        '-o'|'--output') OUT_DIR="$2"; shift 2 ;;
        '-d'|'--domain') TARGET_DOMAINS+=("$2"); shift 2 ;; # Append to array
        '--full-clone') FULL_CLONE=true; shift ;;
        '--cleanup') CLEANUP_REPOS=true; shift ;;
        '--skip-dorking') RUN_DORKING=false; shift ;;
        '--skip-cloning') RUN_CLONING=false; shift ;;
        '--skip-secrets') RUN_SECRETS_SCAN=false; shift ;;
        '--skip-endpoints') RUN_ENDPOINT_EXTRACTION=false; shift ;;
        '--skip-subdomains-code') RUN_SUBDOMAIN_EXTRACTION=false; shift ;;
        '--skip-subfinder') RUN_SUBFINDER=false; shift ;;
        '--skip-httpx') RUN_HTTPX=false; shift ;;
        '--skip-gau') RUN_GAU=false; shift ;;
        '--skip-gowitness') RUN_GOWITNESS=false; shift ;;
        '--skip-nuclei') RUN_NUCLEI=false; shift ;;
        '-h'|'--help') usage ;;
        '-v'|'--version') echo "$SCRIPT_NAME Version $SCRIPT_VERSION"; exit 0 ;;
        '--') shift; break ;; # End of options
        *) error "Internal error! Unexpected option: $1"; usage ;;
    esac
done

# --- Validation and Setup ---

# Validate required arguments
if [[ -z "$GH_TARGET" ]]; then
    error "Target (-t or --target) is required."
    usage
fi

# Set default output directory if not provided
if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="${DEFAULT_OUT_DIR_PREFIX}${GH_TARGET}"
fi

# Create output directory and handle potential errors
mkdir -p "$OUT_DIR"
if [[ $? -ne 0 ]]; then
    error "Failed to create output directory: $OUT_DIR. Check permissions."
    exit 1
fi
# Use absolute path for output directory
OUT_DIR=$(realpath "$OUT_DIR")

# Setup logging
LOG_FILE="$OUT_DIR/recon-run-$(date +%Y%m%d-%H%M%S).log"
# Redirect stdout/stderr to screen and log file. Do this *after* initial checks/setup.
exec > >(tee -a "$LOG_FILE") 2>&1

# Setup Summary Report File
SUMMARY_REPORT_FILE="$OUT_DIR/summary-report.md"
echo "# GitHub Reconnaissance Summary Report for $GH_TARGET" > "$SUMMARY_REPORT_FILE"
echo "**Generated:** $(date)" >> "$SUMMARY_REPORT_FILE"
echo "**Output Directory:** \`$OUT_DIR\`" >> "$SUMMARY_REPORT_FILE"
echo "**Log File:** \`$LOG_FILE\`" >> "$SUMMARY_REPORT_FILE"
echo >> "$SUMMARY_REPORT_FILE"
echo "## Execution Summary" >> "$SUMMARY_REPORT_FILE"

info "Starting Advanced GitHub Reconnaissance Script v$SCRIPT_VERSION"
info "Target: $GH_TARGET"
info "Output Directory: $OUT_DIR"
info "Log File: $LOG_FILE"
info "Summary Report: $SUMMARY_REPORT_FILE"
[[ ${#TARGET_DOMAINS[@]} -gt 0 ]] && info "Target Domains: ${TARGET_DOMAINS[*]}"
[[ "$FULL_CLONE" = true ]] && info "Full Clones: Enabled"
[[ "$CLEANUP_REPOS" = true ]] && info "Cleanup: Enabled"

# --- Prerequisite Checks ---
step "0: Checking Prerequisites..."
check_tool "git" "required"
check_tool "gh" "required"
check_tool "jq" "required"
# Optional tools - checks will happen within functions if step is enabled
check_tool "gitleaks" "optional"
check_tool "trufflehog" "optional"
check_tool "subfinder" "optional"
check_tool "httpx" "optional"
check_tool "gau" "optional"
check_tool "gowitness" "optional"
check_tool "nuclei" "optional"
check_tool "tree" "optional" # For final report
check_tool "awk" "required" # Used internally
check_tool "sed" "required" # Used internally
check_tool "grep" "required" # Used internally
check_tool "sort" "required" # Used internally
check_tool "find" "required" # Used internally
check_tool "wc" "required" # Used internally
check_tool "date" "required" # Used internally
check_tool "mktemp" "required" # Used internally
check_tool "realpath" "required" # Used internally
check_tool "tee" "required" # Used internally

check_gh_auth # Check gh login status
check_rate_limit # Check initial rate limit

# --- Main Execution Flow ---

start_time=$(date +%s)

# Adjust subsequent steps based on --skip-cloning
if [[ "$RUN_CLONING" = false ]]; then
    warn "Skipping cloning (--skip-cloning). Dependent local analysis steps will also be skipped."
    RUN_SECRETS_SCAN=false
    RUN_ENDPOINT_EXTRACTION=false
    RUN_SUBDOMAIN_EXTRACTION=false
    # Add cloning skipped message to summary
    echo "- [Repository Cloning](#repository-cloning): Skipped (--skip-cloning)" >> "$SUMMARY_REPORT_FILE"
fi

# Adjust subsequent steps based on --skip-httpx
if [[ "$RUN_HTTPX" = false ]]; then
    warn "Skipping httpx probing (--skip-httpx). Dependent steps (gau, gowitness, nuclei) will be skipped."
    RUN_GAU=false
    RUN_GOWITNESS=false
    RUN_NUCLEI=false
    # Add httpx skipped message to summary
    echo "- [Live Host Probing (httpx)](#live-host-probing-httpx): Skipped (--skip-httpx)" >> "$SUMMARY_REPORT_FILE"
fi

# Run steps based on flags
[[ "$RUN_DORKING" = true ]] && run_github_dorking || echo "- [GitHub Dorking](#github-dorking): Skipped (--skip-dorking)" >> "$SUMMARY_REPORT_FILE"
[[ "$RUN_CLONING" = true ]] && run_repo_cloning
# These depend on cloning being successful (checked inside run_repo_cloning)
[[ "$RUN_SECRETS_SCAN" = true ]] && run_secrets_scanning || echo "- [Secrets Scanning](#secrets-scanning): Skipped (--skip-secrets or cloning failed/skipped)" >> "$SUMMARY_REPORT_FILE"
[[ "$RUN_ENDPOINT_EXTRACTION" = true ]] && run_endpoint_extraction || echo "- [JS Endpoint Extraction](#js-endpoint-extraction): Skipped (--skip-endpoints or cloning failed/skipped)" >> "$SUMMARY_REPORT_FILE"
[[ "$RUN_SUBDOMAIN_EXTRACTION" = true ]] && run_subdomain_extraction || echo "- [Subdomain Extraction (Code)](#subdomain-extraction-code): Skipped (--skip-subdomains-code or cloning failed/skipped)" >> "$SUMMARY_REPORT_FILE"

[[ "$RUN_SUBFINDER" = true ]] && run_subfinder_enum || echo "- [Subdomain Enumeration (Subfinder)](#subdomain-enumeration-subfinder): Skipped (--skip-subfinder)" >> "$SUMMARY_REPORT_FILE"
[[ "$RUN_HTTPX" = true ]] && run_httpx_probing
# These depend on httpx running successfully
[[ "$RUN_GAU" = true ]] && run_gau_discovery || echo "- https://medium.com/@enessyibrahim/mastering-reconnaissance-with-project-discovery-99d7a21e299a(#url-discovery-gau): Skipped (--skip-gau or httpx failed/skipped)" >> "$SUMMARY_REPORT_FILE"
[[ "$RUN_GOWITNESS" = true ]] && run_gowitness_screenshots || echo "- [Screenshotting (gowitness)](#screenshotting-gowitness): Skipped (--skip-gowitness or httpx failed/skipped)" >> "$SUMMARY_REPORT_FILE"
[[ "$RUN_NUCLEI" = true ]] && run_nuclei_scan || echo "- [Vulnerability Scanning (Nuclei)](#vulnerability-scanning-nuclei): Skipped (--skip-nuclei or httpx failed/skipped)" >> "$SUMMARY_REPORT_FILE"

[[ "$CLEANUP_REPOS" = true ]] && run_cleanup || echo "- [Cleanup](#cleanup): Skipped (cleanup not enabled)" >> "$SUMMARY_REPORT_FILE"

# --- Final Report ---
step "12: Finalizing Report..."
end_time=$(date +%s)
duration=$((end_time - start_time))

echo >> "$SUMMARY_REPORT_FILE" # Add newline before final sections
echo "## Final Summary" >> "$SUMMARY_REPORT_FILE"
echo "**Total Execution Time:** $(date -u -d @${duration} +'%H hours %M minutes %S seconds')" >> "$SUMMARY_REPORT_FILE"
echo "**Output Directory:** [$OUT_DIR]($OUT_DIR)" >> "$SUMMARY_REPORT_FILE"
echo "**Log File:** [$LOG_FILE]($LOG_FILE)" >> "$SUMMARY_REPORT_FILE"
echo "**Summary Report:** [$SUMMARY_REPORT_FILE]($SUMMARY_REPORT_FILE)" >> "$SUMMARY_REPORT_FILE"

success "GitHub Reconnaissance Script Completed for $GH_TARGET"
info "Total execution time: $(date -u -d @${duration} +'%Hh %Mm %Ss')"
info "Output saved in: $OUT_DIR"
info "Summary report generated: $SUMMARY_REPORT_FILE"
info "Detailed log available at: $LOG_FILE"

# Display directory tree if 'tree' command is available
if check_tool "tree" "optional"; then
    info "Output Directory Structure:"
    tree -L 3 "$OUT_DIR"
fi

echo -e "${GREEN}===================== Script End ====================${NC}"
exit 0
