node {
  checkout scm

  String registry = 'docker.darklight.ai'
  String product = 'opencti'
  String branch = "${env.BRANCH_NAME}"
  String commit = "${sh(returnStdout: true, script: 'git rev-parse HEAD')}"
  String commitMessage = "${sh(returnStdout: true, script: "git log --pretty=format:%s -n 1 ${commit}")}"
  String tag = 'latest'
  String graphql = 'https://cyio.darklight.ai/graphql'
  String api = 'api'

  echo "branch: ${branch}, commit message: ${commitMessage}"

  if (branch != 'master') {
    tag = branch.replace('#', '')
    if (branch == 'staging') {
      graphql = 'https://cyio-staging.darklight.ai/graphql'
      api = 'api-staging'
    } else {
      graphql = 'https://cyio-dev.darklight.ai/graphql'
      api = 'api-dev'
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
        String version = readJSON(file: 'package.json')['version']
        echo "version: ${version}"

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
        configFileProvider([
          configFile(fileId: "graphql-env", replaceTokens: true, targetLocation: "opencti-platform/opencti-graphql/.env")
        ]) {
          docker.image('node:16.6.0-alpine3.14').inside("-u root:root") {
            sh label: 'test front', script: '''
              cd opencti-platform/opencti-front
              yarn test || true
            '''

            sh label: 'test graphql', script: '''
              cd opencti-platform/opencti-graphql
              yarn test || true
            '''

            sh label: 'cleanup', script: '''
              rm -rf opencti-platform/opencti-front/node_modules
              rm -rf opencti-platform/opencti-graphql/node_modules
              chown -R 997:997 .
            '''
          }
        }
      } catch (Exception e) {
        // NO-OP
      } finally {
        junit 'opencti-platform/opencti-graphql/test-results/jest/results.xml'
      }
    }
  }, build: {
    stage('Build') {
      if (((branch.equals('master') || branch.equals('staging') || branch.equals('develop')) && !commitMessage.contains('ci:skip')) || commitMessage.contains('ci:build')) {
        dir('opencti-platform') {
          String buildArgs = '--no-cache --progress=plain .'
          docker_steps(registry, product, tag, buildArgs)
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
      } else {
        echo 'Skipping build...'
      }
    }
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
    sh "docker ps -a | grep Exit | cut -d ' ' -f 1 | xargs -r docker rm || true"
    sh 'docker system prune --filter "until=336h" -f'
    sh "rm ${image}.${tag}.tar.gz"
  }
}
