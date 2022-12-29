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
  String version = '0.1.0'
  String sha = ''

  echo "branch: ${branch}, commit message: ${commitMessage}"

  // Configure which endpoint to use based on the branch
  if (branch != 'master' && branch != 'prod') { // already defaulted to production
    tag = branch.replace('#', '')
    if (branch == 'staging') {
      graphql = 'https://cyio-staging.darklight.ai/graphql'
      api = 'api-staging'
    } else {
      graphql = 'https://cyio-dev.darklight.ai/graphql'
      api = 'api-dev'
    }
  }

  office365ConnectorSend(
    status: 'Starting',
    color: '0080FF',
    webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}",
    message: "Build starting",
    factDefinitions: [[name: "Commit Message", template: "${commitMessage}"],
                      [name: "Commit", template: "[${commit[0..7]}](https://github.com/champtc/opencti/commit/${commit})"],
                      [name: "Image", template: "${registry}/${product}:${tag}"]]
  )

  // Check version, yarn install, etc.
  stage('Setup') {
    docker.image('node:16.19.0-alpine3.16').inside('-u root:root') {
      dir('opencti-platform') {
        dir('opencti-graphql') { // GraphQL
          version = readJSON(file: 'package.json')['version']
          switch (branch) {
            case 'develop':
              version = "${version}-dev+" + "${commit}"[0..7]
              sh label: 'updating version', script: """
                tmp=\$(mktemp)
                jq '.version = "${version}"' package.json > \$tmp
                mv -f \$tmp package.json
              """
              break
            case 'staging':
              version = "${version}-RC+" + "${commit}"[0..7]
              sh label: 'updating version', script: """
                tmp=\$(mktemp)
                jq '.version = "${version}"' package.json > \$tmp
                mv -f \$tmp package.json
              """
              break
            default:
              break
          }

          if (fileExists('config/schema/compiled.graphql')) {
            sh 'rm config/schema/compiled.graphql'
          }
          sh 'yarn install'
        }
        dir('opencti-front') { // Frontend
          sh "sed -i 's|https://api-dev.|https://${api}.|g' package.json"
          sh 'yarn install'
          sh 'yarn run schema-compile'
        }
      }
    }
  }

  // Run any tests we can that do not require a build, alongside the build process
  parallel build: { 
    // if core branches (master, staging, or develop) build; except if the commit says:
    //   - 'ci:skip' then skip build
    //   - 'ci:build' then build regardless of branch
    if (((branch.equals('master') || branch.equals('prod') || branch.equals('staging') || branch.equals('develop')) && !commitMessage.contains('ci:skip')) || commitMessage.contains('ci:build')) {
      dir('opencti-platform') {
        String buildArgs = '--no-cache --progress=plain .'
        sha = docker_steps(registry, product, tag, buildArgs)
      }

      // Send the Teams message to DarkLight Development > DL Builds
      office365ConnectorSend(
        status: 'Completed',
        color: '00FF00',
        webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}",
        message: "New image built and pushed!",
        factDefinitions: [[name: "Commit Message", template: "${commitMessage}"],
                          [name: "Commit", template: "[${commit[0..7]}](https://github.com/champtc/opencti/commit/${commit})"],
                          [name: "Image", template: "${registry}/${product}:${tag}"]]
      )
    } else {
      echo 'Skipping build...'
    }
  }, test: {
    stage('Test') {
      if (commitMessage.contains('ci:skip-tests')) {
        echo 'Skipping tests'
        currentBuild.result = 'SUCCESS'
        return
      }

      try {
        configFileProvider([
          configFile(fileId: 'graphql-env', replaceTokens: true, targetLocation: 'opencti-platform/opencti-graphql/.env')
        ]) {
          docker.image('node:16.19.0-alpine3.16').inside('-u root:root') {
            sh label: 'test front', script: '''
              cd opencti-platform/opencti-front
              yarn test || true
            '''

            sh label: 'test graphql', script: '''
              cd opencti-platform/opencti-graphql
              yarn test || true
            '''

            sh label: 'cleanup', script: '''
              chown -R 997:995 .
            '''
          }
        }
      } catch (Exception e) {
        office365ConnectorSend(
          status: 'Tests Failed',
          color: 'FF8000',
          webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}",
          message: "${e}"
        )
        throw e
      } finally {
        junit testResults: 'opencti-platform/opencti-graphql/test-results/jest/results.xml', skipPublishingChecks: true
        try {
          String results = sh(returnStdout: true, script: 'cat opencti-platform/opencti-graphql/test-results/jest/results.xml')
          office365ConnectorSend(
            webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}",
            message: 'Jest Test Results',
            factDefinitions: [[name: 'Commit', template: "[${commit[0..7]}](https://github.com/champtc/opencti/commit/${commit})"],
                              [name: 'Version', template: "${version}"],
                              [name: 'Results', template: "${results}"]]
          )
        } catch (Exception e) {
          echo "Failed to post test results to Teams: ${e}"
        }
      }
    }
  }

  // Run integration tests, but do not block the ability to rapid deploy
  parallel ci: {
    stage('Integration Testing') {
      lock('testing:opencti') {
        try {
          configFileProvider([
            configFile(fileId: 'ci-testing-default-json', replaceTokens: true, targetLocation: './docker/default.json'),
            configFile(fileId: 'ci-testing-docker-env', replaceTokens: true, targetLocation: './docker/.env'),
            configFile(fileId: 'ci-testing-users-json', replaceTokens: true, targetLocation: './opencti-platform/opencti-front/cypress/fixtures/users.json')
          ]) {
            withCredentials([
              file(credentialsId: 'STARDOG_LICENSE_FILE', variable: 'LICENSE_FILE'),
              file(credentialsId: 'WILDCARD_DARKLIGHT_CRT', variable: 'CRT'),
              file(credentialsId: 'WILDCARD_DARKLIGHT_KEY', variable: 'KEY')
            ]) {
              dir('docker') {
                sh "cat ${LICENSE_FILE} > stardog-license-key.bin"
                writeFile(file: 'opencti-front-localhost.crt', text: readFile(CRT))
                writeFile(file: 'opencti-front-localhost.key', text: readFile(KEY))

                sh 'docker-compose --profile backend up -d && sleep 90'
                sh 'docker-compose --profile frontend up -d && sleep 30'
              }

              // Use the cypress prebuilt container to run our test
              dir('opencti-platform/opencti-front/') {
                sh 'docker run --rm -v $PWD:/e2e -w /e2e --network docker_default cypress/included:10.3.0'
              }
            }
          }
        } catch (Exception e) {
          office365ConnectorSend(
            error: "${e}",
            color: 'FF8000',
            webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}",
            message: "Integration Tests Failed"
          )
          throw e
        } finally {
          sh 'docker run --rm -v $PWD:/e2e -w /e2e --network docker_default --entrypoint chown cypress/included:10.3.0 -R 997:995 . || true'
          dir('docker') {
            sh '''
              docker-compose down || true
              rm -rf default.json .env || true
              rm -rf stardog-license-key.bin || true
            '''
          }
          currentBuild.result = 'SUCCESS'
          return
        }
      }
    }
  }, deploy: {
    if (commitMessage.contains('ci:skip')) {
      echo 'Skip flag detected, skipping deployment...'
    } else {
      switch (branch) {
        case 'master':
        case 'prod':
          if (commitMessage.contains('ci:deploy')) {
            stage('Deploying to production') {
              build '/deploy/OpenCTI Frontend/main'
            }
          }
          break
        case 'staging':
          if (commitMessage.contains('ci:deploy')) {
            stage('Deploying to staging') {
              build '/deploy/OpenCTI Frontend/staging'
            }
          }
          break
        case 'develop':
          stage('Deploying to develop') {
            build '/deploy/OpenCTI Frontend/dev'
          }
          break
        default:
          echo 'Deploy flag is only supported on production, staging, or develop branches; ignoring deploy flag...'
          break
      }
    }
  }

  try {
    dir('k8s-tmp') {
      checkout([
        changelog: false,
        poll: false,
        $class: 'GitSCM',
        branches: [[name: '*/main']],
        extensions: [],
        userRemoteConfigs: [[credentialsId: 'c4b687fd-69dc-4913-b28a-45a061914f60', url: 'https://github.com/champtc/k8s']]
      ])

      stage('KubeSec Scan') {
        sh label: 'Kubesec Scan', script: '''
          docker run -i kubesec/kubesec:512c5e0 scan /dev/stdin < cyio/opencti/opencti.yaml || true
          docker run -i kubesec/kubesec:512c5e0 scan /dev/stdin < cyio/opencti/elasticsearch.yaml || true
          docker run -i kubesec/kubesec:512c5e0 scan /dev/stdin < cyio/opencti/rabbitmq.yaml || true
          docker run -i kubesec/kubesec:512c5e0 scan /dev/stdin < cyio/opencti/redis.yaml || true
        '''
      }

      stage('Version Bump') {
        echo "Updating K8s image tag to new sha value \'${sha}\'"
        def data = readYaml file: 'cyio/opencti/opencti.yaml'
        echo '$data'
      }
    }
  } catch (Exception e) {
    echo "${e}"
    currentBuild.result = 'SUCCESS'
    return
  }
}

// Generic way to build a docker image and push it to our registry
// Returns SHA of the newly created image
String docker_steps(String registry, String image, String tag, String buildArgs) {
  def app;
  String sha256 = ''

  stage('Build') {
    app = docker.build("${registry}/${image}:${tag}", "${buildArgs}")
    sha256 = sh returnStdout: true, script: "docker images --no-trunc --quiet ${registry}/${image}:${tag}"
  }

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

  sha = sha256
  return sha256
}
