node {
  try {
    String registry = 'docker.darklight.ai'
    String product = 'opencti'
    String branch = "${env.BRANCH_NAME}"

    if (branch != 'master' && branch != 'main') {
      product += '-' + branch
    }

    ws("${env.WS_FOLDER}/docker/opencti/${branch}/") {
      stage('Clone Repository') {
        checkout scm
      }

      parallel frontend: {
        String buildArgs = '--no-cache -f ./opencti-platform/opencti-front/Dockerfile opencti-platform'
        docker_steps(registry, "${product}-frontend", buildArgs)
      }, backend: {
        String buildArgs = '--no-cache ./opencti-platform/opencti-graphql/'
        docker_steps(registry, "${product}-backend", buildArgs)
      }

      stage('Clean Local Docker Resources') {
        /**
          --filter "until 336h": Don't consider Docker resources unless they are at least 2 weeks old (336 hours)
          -f: force prune, needed to avoid prompting the user
        **/
        sh(returnStdout: false, script: 'docker system prune --filter "until=336h" -f')
      }
    }
  } catch(Exception ex) {
    office365ConnectorSend status: 'Failed', webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}"
    throw ex
  }
}

void docker_steps(String registry, String image, String buildArgs) {
  stage('Build') {
    docker.build("${registry}/${image}", "${buildArgs}")
  }

  stage('Save') {
    sh "docker save ${registry}/${image} | gzip > ${image}.tar.gz"
  }

  stage('Archive') {
    archiveArtifacts artifacts: "${image}.tar.gz", fingerprint: true, followSymlinks: false
  }

  stage('Clean') {
    sh "docker ps -a | grep Exit | cut -d ' ' -f 1 | xargs docker rm || true"
    sh "rm ${image}.tar.gz"
  }
}
