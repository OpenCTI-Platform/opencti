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
        docker_steps(registry, "${product}-frontend", '--no-cache -f ./opencti-platform/opencti-front/Dockerfile opencti-platform')
      }, backend: {
        docker_steps(registry, "${product}-backend", '--no-cache ./opencti-platform/opencti-graphql/')
      }

      stage('Clean Local Docker Resources') {
        /**
          --filter "until 336h": Don't consider Docker resources unless they are at least 2 weeks old (336 hours)
          -f: force prune, needed to avoid prompting the user
        **/
        sh(returnStdout: false, script: 'docker system prune --filter "until=336h" -f')
      }
    }

    office365ConnectorSend (
      status: 'Completed',
      color: '00FF00',
      webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}",
      message: 'New images built!',
      factDefinitions: [[name: 'OpenCTI', template: "docker pull ${image}"]]
    )
  } catch(Exception ex) {
    office365ConnectorSend status: 'Failed', webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}"
    throw ex
  }
}

void docker_steps(String registry, String image, String buildArgs) {
  stage('Build') {
    docker.build("${registry}/${image}", "${buildArgs}")
  }

  stage('Export') {
    sh "docker save ${registry}/${image} | gzip > ${image}.tar.gz"
  }

  stage('Save') {
    archiveArtifacts "${image}.tar.gz", fingerprint: true, followSymlinks: false
  }

  stage('Clean') {
    sh "rm ${image}.tar.gz"
  }
}
