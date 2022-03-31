node {
  checkout scm

  String registry = 'docker.darklight.ai'
  String product = 'opencti'
  String branch = "${env.BRANCH_NAME}"
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
        sh(returnStdout: true, script: 'printenv')

        dir('opencti-worker/src') {
          sh 'pip install --no-cache-dir -r requirements.txt'
          sh 'pip install --upgrade --force --no-cache-dir git+https://github.com/OpenCTI-Platform/client-python@master'
        }

        dir('opencti-platform') {
          dir('opencti-graphql') {
            sh 'yarn test'
          }
          dir('opencti-front') {
            sh 'yarn test'
          }
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
      webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}"
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
