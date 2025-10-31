#!/bin/sh

if [[ -z "$1" ]] || [[ -z "$2" ]] || [[ -z "$3" ]]
then
    echo "[CLONE-DEPS] This scripts $0 requires 3 parameters: branch_name:$1, pr_target_branch: $2, workspace:$3 (optional: PR_number:$4)"
    exit 0
fi

PR_BRANCH_NAME=$1
PR_TARGET_BRANCH=$2
WORKSPACE=$3
PR_NUMBER=$4

CONNECTOR_DIR="${WORKSPACE}/opencti-connectors"
echo "CONNECTOR_DIR=${CONNECTOR_DIR}"

# For PR build, we check if api-test can be skipped
# Keeping old function name during client-python migration, will rename after.
clone_for_pr_build() {
    cd ${WORKSPACE}
    export GH_TOKEN="${GITHUB_TOKEN}"

    gh auth login --hostname github.com --with-token ${GH_TOKEN}
    gh auth status
    gh repo set-default https://github.com/OpenCTI-Platform/opencti
    gh repo clone https://github.com/OpenCTI-Platform/connectors ${CONNECTOR_DIR} -- --depth=1

    cd ${WORKSPACE}
    CHANGES_OUSTIDE_FRONT_COUNT=$(gh pr diff ${PR_NUMBER} --name-only | grep -v "opencti-platform/opencti-front" | wc -l)
    if [[ ${CHANGES_OUSTIDE_FRONT_COUNT} -eq 0 ]]
    then
        echo "[CLONE-DEPS][BUILD] Only frontend changes on this PR, api-test can be skipped."
        touch "${WORKSPACE}/api-test.skip"
    else
        echo "[CLONE-DEPS][BUILD] There is more than frontend changes, api-test will be run."
    fi
}

# For branch only build (like master or release/current) we skip nothing.
# Keeping old function name during client-python migration, will rename after.
clone_for_push_build() {
    # It's the fallback script, but the issue here is that push build is started without any PR.
    # it's still needed on some use case, a like a first push build.
    echo "[CLONE-DEPS][CONNECTOR] Build from a commit, cloning connector on ${CONNECTOR_DIR}."
    gh repo clone https://github.com/OpenCTI-Platform/connectors ${CONNECTOR_DIR} -- --depth=1
}

echo "[CLONE-DEPS] START; with PR_BRANCH_NAME=${PR_BRANCH_NAME},PR_TARGET_BRANCH=${PR_TARGET_BRANCH}, PR_NUMBER=${PR_NUMBER}, OPENCTI_DIR=${OPENCTI_DIR}."
if [[ -z ${PR_NUMBER} ]] || [[ ${PR_NUMBER} == "" ]]
then
    # No PR number from Drone = "Push build".
    # Using github cli to get PR number anyway
    PR_NUMBER=$(gh pr view ${PR_BRANCH_NAME} --json number --jq '.number')
    PR_TARGET_BRANCH=$(gh pr view ${PR_BRANCH_NAME} --json baseRefName --jq '.baseRefName')

    if [[ -z ${PR_NUMBER} ]] || [[ ${PR_NUMBER} == "" ]]
    then
        echo "[CLONE-DEPS] PR is not created on github yet, using clone without PR number and default fallback to master"
        clone_for_push_build
    else
        echo "[CLONE-DEPS] Got data from github cli, can continue with: PR_TARGET_BRANCH=${PR_TARGET_BRANCH}, PR_NUMBER=${PR_NUMBER}."
        clone_for_pr_build
    fi
else
    # PR build is trigger from Pull Request coming both from branch and forks.
    # We need to have this clone accross repository that works for forks (community PR)
    echo "[CLONE-DEPS] Got PR number ${PR_NUMBER} from Drone = "PR build"; Pull Request coming both from branch and forks."
    clone_for_pr_build
fi

cd ${CONNECTOR_DIR}
echo "[CLONE-DEPS] END; Using connectors on branch:$(git branch --show-current)"

cd ${WORKSPACE}