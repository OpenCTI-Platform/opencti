set -e
for script in ./*.py; do
  if [[ $script == *"cmd_line_tag_latest_indicators_of_threat.py"* || $script == *"upload_artifacts.py"* ]]; then
    # TODO special execution for cmd tools
    continue
  fi
  python3 $script;
done