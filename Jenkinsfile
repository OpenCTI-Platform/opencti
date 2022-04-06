node {
  checkout scm

  String registry = 'docker.darklight.ai'
  String product = 'opencti'
  String branch = "${env.BRANCH_NAME}"
  String commit = "${sh(returnStdout: true, script: 'git rev-parse HEAD')}"
  String commitMessage = "${env.COMMIT_MESSAGE}"
  String tag = 'latest'
  String graphql = 'https://cyio.darklight.ai/graphql'
  String api = 'api'

  if (branch != 'master' && branch != 'main') {
    if (branch == 'develop') {
      tag = branch
      graphql = 'https://cyio-dev.darklight.ai/graphql'
      api = 'api-dev'
    } else if (branch == 'staging') {
      tag = branch
      graphql = 'https://cyio-staging.darklight.ai/graphql'
      api = 'api-staging'
    } else if (branch == 'AB#4896') {
      tag = 'ab4896'
      graphql = 'https://cyio-dev.darklight.ai/graphql'
      api = 'api-dev'
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
        dir('src/relay') {
          sh "sed -i 's|\${hostUrl}/graphql|${graphql}|g' environmentDarkLight.js"
          archiveArtifacts artifacts: 'environmentDarkLight.js', fingerprint: true, followSymlinks: false
        }
        sh "sed -i 's|https://api-dev.|https://${api}.|g' package.json"
        archiveArtifacts artifacts: 'package.json', fingerprint: true, followSymlinks: false
        sh 'yarn schema-compile'
        sh 'yarn install'
      }
    }
  }

  parallel test: {
    stage('Test') {
      try {
        def tmp = sh(returnStdout: true, script: "mktemp -d")

        docker.image('node:16.6.0-alpine3.14').inside("-v ${tmp}:/.cache/yarn") {
          sh '''
            node --version
            npm --version

            cd opencti-platform/opencti-front && \
              yarn install --network-timeout 300000 --frozen-lockfile && \
              yarn cache clean --all
              yarn test
          '''
        }
      } catch(Exception e) {
        // NO-OP
      }
    }
  }, build: {
    stage('Build') {
      dir('opencti-platform') {
        String buildArgs = '--no-cache --progress=plain .'
        docker_steps(registry, product, tag, buildArgs)
      }
    }

    office365ConnectorSend(
      status: 'Completed',
      color: '00FF00',
      webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}",
      message: "New image built and pushed!",
      factDefinitions: [[name: "Commit Message", template: "${commitMessage}"],
                        [name: "Commit SHA", template: "${commit}"], 
                        [name: "Image", template: "${registry}/${product}:${tag}"]]
    )
  }
}

void docker_steps(String registry, String image, String tag, String buildArgs) {
  def app = docker.build("${registry}/${image}:${tag}", "${buildArgs}")

  stage('Save') {
    sh "docker save ${registry}/${image}:${tag} | gzip > ${image}.${tag}.tar.gz"
  }

  stage('Archive') {
    archiveArtifacts artifacts: "${image}.${tag}.tar.gz", fingerprint: true, followSymlinks: false
  }

  stage('Push') {
    docker.withRegistry("https://${registry}", 'docker-registry-credentials') {
      app.push("${tag}")
    }
  }

  stage('Clean') {
    sh "docker ps -a | grep Exit | cut -d ' ' -f 1 | xargs docker rm || true"
    sh 'docker system prune --filter "until=336h" -f'
    sh "rm ${image}.${tag}.tar.gz"
  }
}
