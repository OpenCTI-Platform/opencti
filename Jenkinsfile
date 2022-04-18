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

  echo "branch: ${branch}, commit message: ${commitMessage}"

  // Configure which endpoint to use based on the branch
  if (branch != 'master') { // already defaulted to production
    tag = branch.replace('#', '')
    if (branch == 'staging') {
      graphql = 'https://cyio-staging.darklight.ai/graphql'
      api = 'api-staging'
    } else {
      graphql = 'https://cyio-dev.darklight.ai/graphql'
      api = 'api-dev'
    }
  }

  // Check version, yarn install, etc.
  stage('Setup') {
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
        echo "version: ${version}"

        if (fileExists('config/schema/compiled.graphql')) {
          sh 'rm config/schema/compiled.graphql'
        }
        sh 'yarn install'
      }
      dir('opencti-front') { // Frontend
        // TODO: investigate
        // Hardcode the endpoints for now, should use envionment variables
        dir('src/relay') {
          sh "sed -i 's|\${hostUrl}/graphql|${graphql}|g' environmentDarkLight.js"
        }
        sh "sed -i 's|https://api-dev.|https://${api}.|g' package.json"
        sh 'yarn schema-compile'
        sh 'yarn install'
      }
    }
  }

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

  stage('Build') {
    // if main branches (master, staging, or develop) build, except if:
    //   - commit says: 'ci:skip' then skip build
    //   - commit says: 'ci:build' then build regardless of branch
    if (((branch.equals('master') || branch.equals('staging') || branch.equals('develop')) && !commitMessage.contains('ci:skip')) || commitMessage.contains('ci:build')) {
      office365ConnectorSend(
        // status: 'Build Started',
        // color: '00FF00',
        webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}",
        message: "Build started",
        factDefinitions: [[name: "Commit", template: "[${commit[0..7]}](https://github.com/champtc/opencti/commit/${commit})"],
                          [name: "Version", template: "${version}"]]
      )

      dir('opencti-platform') {
        String buildArgs = '--no-cache --progress=plain .'
        docker_steps(registry, product, tag, buildArgs)
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
  }

  // TODO: Actually call the Jenkins job
  if (commitMessage.contains('ci:deploy')) {
    stage('Deploy') {
      switch(branch) {
        case 'master':
          echo 'Deploying to production...'
          // build '/deploy/OpenCTI Frontend/main'
          break
        case 'staging':
          echo 'Deploying to staging...'
          build '/deploy/OpenCTI Frontend/staging'
          break
        case 'develop':
          echo 'Deploying to develop...'
          // build '/deploy/OpenCTI Frontend/dev'
          break
        default:
          echo "Deploy flag is only supported on production, staging, or develop branches; ignoring deploy flag..."
          break
      }
    }
  }
}

// Generic way to build a docker image and push it to our registry
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
