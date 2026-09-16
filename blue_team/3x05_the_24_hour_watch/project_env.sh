#!/bin/bash

export CAPSTONE_PACK="$HOME/evidence_pack_secondary"
export ASSETS_DIR="$HOME/3x05_assets/capstone_pack/meta"
export WAZUH_EXPORTS="$HOME/3x05_assets/wazuh_exports"
export PROJECT_DIR="$HOME/dlh-cyber_security/blue_team/3x05_the_24_hour_watch"
export SHIFT_WORKSPACE="$PROJECT_DIR"
export HANDOFF_DIR="$HOME/3x00_handoff/evidence_handoff"

export PIPELINE_BIN="$HOME/bt/3x00/pipeline/run_pipeline.sh"
export BASELINE_BIN="$PROJECT_DIR/build_baseline.sh"
export CATALOG_DIR="$HOME/3x02_package/detection_catalog"
export TRIAGE_BIN="$PROJECT_DIR/triage.sh"

export BASELINE_PKG="$HOME/3x01_package/baseline_package"
export TRIAGE_PKG="$HOME/3x03_package/triage_package"

export PATH="$PROJECT_DIR/bin:$PATH"

export CATALOG_DIR="$HOME/dlh-cyber_security/blue_team/3x02_the_alert_factory"
