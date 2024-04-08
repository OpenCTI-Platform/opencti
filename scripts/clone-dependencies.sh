#!/bin/sh

if [[ -z "$1" ]] || [[ -z "$2" ]]
then
    echo "[CLONE-DEPS] This scripts $0 requires 2 paramaters: branch_name:$1, workspace:$2 (optional: PR_number:$3)"
    exit 0
fi

PR_BRANCH_NAME=$1
WORKSPACE=$2
PR_NUMBER=$3


CLI_PYTHON_DIR="${WORKSPACE}/client-python"
CONNECTOR_DIR="${WORKSPACE}/opencti-connectors"
echo "CLI_PYTHON_DIR=${CLI_PYTHON_DIR}"
echo "CONNECTOR_DIR=${CONNECTOR_DIR}"

clone_for_pr_build() {
    cd ${WORKSPACE}
    export GH_TOKEN="${GITHUB_TOKEN}"

    gh auth login --hostname github.com --with-token ${GH_TOKEN}
    gh auth status
    gh repo set-default https://github.com/OpenCTI-Platform/opencti

    #Check current PR to see if label "multi-repository" is set
    IS_MULTI_REPO=$(gh pr view ${PR_NUMBER} --json labels | grep -c "multi-repository")
    if [[ ${IS_MULTI_REPO} -eq 1 ]]
    then
        TARGET_BRANCH="${PR_BRANCH_NAME}"

        # ------
        # For client-python, maybe one day we will refactor to a function.
        echo "[CLONE-DEPS][CLIENT-PYTHON] Multi repository PR, looking for client-python related branch"
        gh repo clone https://github.com/OpenCTI-Platform/client-python ${CLI_PYTHON_DIR}
        cd ${CLI_PYTHON_DIR}

        # search for the first opencti PR that matches OPENCTI_BRANCH
        gh repo set-default https://github.com/OpenCTI-Platform/client-python
        gh pr list --label "multi-repository" > multi-repo-cli-python-prs.txt

        cat multi-repo-cli-python-prs.txt

        CLI_PYTHON_PR_NUMBER=$(cat multi-repo-cli-python-prs.txt | grep "${TARGET_BRANCH}" | head -n 1 | sed 's/#//g' | awk '{print $1}')
        echo "CLI_PYTHON_PR_NUMBER=${CLI_PYTHON_PR_NUMBER}"

        if [[ "${CLI_PYTHON_PR_NUMBER}" != "" ]]
        then
            echo "[CLONE-DEPS][CLIENT-PYTHON] Found a PR in client-python with number ${CLI_PYTHON_PR_NUMBER}, using it."
            gh pr checkout ${CLI_PYTHON_PR_NUMBER}
            pip install -e .
        else
            echo "[CLONE-DEPS][CLIENT-PYTHON] No PR found in client-python side, keeping client-python:master"
            # Repository already clone on master branch
        fi

        # ------
        # For connector, maybe one day we will refactor to a function.
        echo "[CLONE-DEPS][CONNECTOR] Multi repository PR, looking for connectors related branch"
        gh repo clone https://github.com/OpenCTI-Platform/connectors ${CONNECTOR_DIR}
        cd ${CONNECTOR_DIR}

        # search for the first opencti PR that matches OPENCTI_BRANCH
        gh repo set-default https://github.com/OpenCTI-Platform/connectors
        gh pr list --label "multi-repository" > multi-repo-connector-prs.txt

        cat multi-repo-connector-prs.txt

        CONNECTOR_PR_NUMBER=$(cat multi-repo-connector-prs.txt | grep "${TARGET_BRANCH}" | head -n 1 | sed 's/#//g' | awk '{print $1}')
        echo "CONNECTOR_PR_NUMBER=${CONNECTOR_PR_NUMBER}"

        if [[ "${CONNECTOR_PR_NUMBER}" != "" ]]
        then
            echo "[CLONE-DEPS][CONNECTOR] Found a PR in connectors with number ${CONNECTOR_PR_NUMBER}, using it."
            gh pr checkout ${CONNECTOR_PR_NUMBER}
        else
            echo "[CLONE-DEPS][CONNECTOR] No PR found in connectors side, keeping connector:master"
            # Repository already clone on master branch
        fi
        
    else
        echo "[CLONE-DEPS] NOT multi repo, cloning client-python:master and connector:master"
        gh repo clone https://github.com/OpenCTI-Platform/client-python ${CLI_PYTHON_DIR}
        gh repo clone https://github.com/OpenCTI-Platform/connectors ${CONNECTOR_DIR}
    fi
}

clone_for_push_build() {
    echo "[CLONE-DEPS][CLIENT-PYTHON] Build from a commit, checking if a dedicated branch is required."
    if [[ "$(echo "$(git ls-remote --heads https://github.com/OpenCTI-Platform/client-python.git refs/heads/$PR_BRANCH_NAME)")" != '' ]]
    then
        CLIENT_PYTHON_BRANCH=${PR_BRANCH_NAME}
    else
        CLIENT_PYTHON_BRANCH=$([[ "$(echo "$(git ls-remote --heads https://github.com/OpenCTI-Platform/client-python.git refs/heads/opencti/$PR_BRANCH_NAME)")" != '' ]] && echo opencti/$PR_BRANCH_NAME || echo 'master')
    fi
    git clone -b $CLIENT_PYTHON_BRANCH https://github.com/OpenCTI-Platform/client-python.git ${CLI_PYTHON_DIR}

    echo "[CLONE-DEPS][CONNECTOR] Build from a commit, checking if a dedicated branch is required."
    if [[ "$(echo "$(git ls-remote --heads https://github.com/OpenCTI-Platform/connectors.git refs/heads/$PR_BRANCH_NAME)")" != '' ]]
    then
        CONNECTOR_BRANCH=${PR_BRANCH_NAME}
    else
        CONNECTOR_BRANCH=$([[ "$(echo "$(git ls-remote --heads https://github.com/OpenCTI-Platform/connectors.git refs/heads/opencti/$PR_BRANCH_NAME)")" != '' ]] && echo opencti/$PR_BRANCH_NAME || echo 'master')
    fi

    git clone -b $CONNECTOR_BRANCH https://github.com/OpenCTI-Platform/connectors.git ${CONNECTOR_DIR}
}

echo "[CLONE-DEPS] START; with PR_BRANCH_NAME=${PR_BRANCH_NAME}, PR_NUMBER=${PR_NUMBER}, OPENCTI_DIR=${OPENCTI_DIR}."
if [[ -z ${PR_NUMBER} ]] || [[ ${PR_NUMBER} == "" ]]
then
    # No PR number from Drone = "Push build". And it's only for repository branch (not fork)
    # Only check branches from OpenCTI-Platform org
    echo "[CLONE-DEPS] No PR number from Drone = "Push build"; it's only for repository branch (not fork)."
    clone_for_push_build
else
    # PR build is trigger from Pull Request coming both from branch and forks.
    # We need to have this clone accross repository that works for forks (community PR)
    echo "[CLONE-DEPS] Got PR number ${PR_NUMBER} from Drone = "PR build"; Pull Request coming both from branch and forks."
    clone_for_pr_build
fi

cd ${CONNECTOR_DIR}
echo "[CLONE-DEPS] END; Using connectors on branch:$(git branch --show-current)"
cd ${CLI_PYTHON_DIR}
echo "[CLONE-DEPS] END; Using client-python on branch:$(git branch --show-current)"

cd ${WORKSPACE}