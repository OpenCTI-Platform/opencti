node {
  checkout scm

  String registry = 'docker.darklight.ai'
  String product = 'opencti'
  String branch = "${env.BRANCH_NAME}"
  String tag = 'latest'

  if (branch != 'master' && branch != 'main') {
    if (branch == 'develop' || branch == 'staging') {
      tag = branch
    } else {
      throw new Exception("Somehow a branch that was not suppose to cause a build, did. Branch: ${branch}")
    }
  }

  stage('Setup') {
    dir('opencti-platform') {
      dir('opencti-graphql') {
        if (fileExists('config/schema/compiled.graphql')) {
          sh 'rm config/schema/compiled.graphql'
        }
        sh 'yarn install'
      }
      dir('opencti-front') {
        sh 'yarn schema-compile'
        sh 'yarn install'
      }
    }
  }

  String buildArgs = '--no-cache --progress=plain'
  docker_steps(registry, product, tag, buildArgs)

  office365ConnectorSend(
    status: 'Completed',
    color: '00FF00',
    webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}"
  )
}

void docker_steps(String registry, String image, String tag, String buildArgs) {
  stage('Build') {
    docker.build("${registry}/${image}:${tag}", "${buildArgs}")
  }

  stage('Save') {
    sh "docker save ${registry}/${image}:${tag} | gzip > ${image}.${tag}.tar.gz"
  }

  stage('Archive') {
    archiveArtifacts artifacts: "${image}.${tag}.tar.gz", fingerprint: true, followSymlinks: false
  }

  stage('Push') {
    docker.push("${registry}/${image}:${tag}")
  }

  stage('Clean') {
    sh "docker ps -a | grep Exit | cut -d ' ' -f 1 | xargs docker rm || true"
    sh 'docker system prune --filter "until=336h" -f'
    sh "rm ${image}.${tag}.tar.gz"
  }
}
