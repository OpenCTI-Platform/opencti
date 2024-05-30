#!/bin/sh

if [[ -z "$1" ]] || [[ -z "$2" ]] || [[ -z "$3" ]]
then
    echo "[CLONE-DEPS] This scripts $0 requires 3 paramaters: branch_name:$1, workspace:$2 (optional: PR_number:$3)"
    exit 0
fi

PR_BRANCH_NAME=$1
WORKSPACE=$2
PR_NUMBER=$3

OPENCTI_DIR="${WORKSPACE}/opencti"

clone_for_pr_build() {
    cd ${WORKSPACE}
    export GH_TOKEN="${GITHUB_TOKEN}"

    gh auth login --hostname github.com --with-token ${GH_TOKEN}
    gh auth status
    gh repo set-default https://github.com/OpenCTI-Platform/client-python

    #Check current PR to see if label "multi-repository" is set
    IS_MULTI_REPO=$(gh pr view ${PR_NUMBER} --json labels | grep -c "multi-repository")
    if [[ ${IS_MULTI_REPO} -eq 1 ]]
    then

        OPENCTI_BRANCH=${PR_BRANCH_NAME}
        echo "[CLONE-DEPS]  Multi repository PR, looking for opencti related branch"
        if [[ $(echo ${PR_BRANCH_NAME} | cut -d "/" -f 1) == "opencti" ]]
        then
            #remove opencti prefix when present
            OPENCTI_BRANCH=$(echo ${PR_BRANCH_NAME} | cut -d "/" -f2-)
        fi
        echo "[CLONE-DEPS] OPENCTI_BRANCH is ${OPENCTI_BRANCH}"
        gh repo clone https://github.com/OpenCTI-Platform/opencti ${OPENCTI_DIR}
        cd ${OPENCTI_DIR}

        # search for the first opencti PR that matches OPENCTI_BRANCH
        gh repo set-default https://github.com/OpenCTI-Platform/opencti
        gh pr list --label "multi-repository" > multi-repo-prs.txt

        cat multi-repo-prs.txt

        OPENCTI_PR_NUMBER=$(cat multi-repo-prs.txt | grep "${OPENCTI_BRANCH}" | head -n 1 | sed 's/#//g' | awk '{print $1}')
        echo "OPENCTI_PR_NUMBER=${OPENCTI_PR_NUMBER}"

        if [[ "${OPENCTI_PR_NUMBER}" != "" ]]
        then
            echo "[CLONE-DEPS] Found a PR in opencti with number ${OPENCTI_PR_NUMBER}, using it."
            gh pr checkout ${OPENCTI_PR_NUMBER}
        else
            echo "[CLONE-DEPS] No PR found in opencti side, keeping opencti:master"
            # Repository already clone on master branch
        fi
        
    else
        echo "[CLONE-DEPS] NOT multi repo, cloning opencti:master"
        gh repo clone https://github.com/OpenCTI-Platform/opencti ${OPENCTI_DIR}
    fi
}

clone_for_push_build() {
    echo "[CLONE-DEPS]  Build from a commit, checking if a dedicated branch is required."
    OPENCTI_BRANCH=$([ $(echo $PR_BRANCH_NAME | cut -d "/" -f 1) == opencti ] && echo $(echo $PR_BRANCH_NAME | cut -d "/" -f2-) || echo 'master' )
    git clone -b $OPENCTI_BRANCH https://github.com/OpenCTI-Platform/opencti.git
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

cd ${OPENCTI_DIR}
echo "[CLONE-DEPS] END; Using opencti on branch:$(git branch --show-current)"

cd ${WORKSPACE}