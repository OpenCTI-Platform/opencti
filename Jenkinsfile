node {
  try {
    def registry = "docker.darklight.ai";
    def product = "opencti"
    def branch = "${env.BRANCH_NAME}"
    def version = "${env.BUILD_NUMBER}"
    def versionsToKeep = 3;

    if (branch != "master" || branch != "main") {
      product += '-' + branch;
    }

    stage('Detect Version') {
      def jsPackage = readJSON file: 'opencti-platform/opencti-front/package.json';
      if (jsPackage['version'] != null) {
        version = jsPackage['version'];
      }
    }

    def image = "${registry}/${product}";
    def app;

    ws("${env.WS_FOLDER}/docker/${product}/${branch}/") {
      stage('Clone Repository') {
        checkout scm
      }

      stage('Build') {
        dir('opencti-platform/') {
          app = docker.build("${image}", "--no-cache .")
        }
      }

      docker.withRegistry("https://${registry}", "docker-registry-credentials") {
        stage('Push') {
          app.push("latest")
          app.push("${version}")
        }

        stage('Clean Remote Docker Images') {
          withCredentials([usernameColonPassword(credentialsId: 'docker-registry-credentials', variable: 'USERPASS')]) {
            def allTags = sh(returnStdout: true, script: 'curl -u $USERPASS -k -X GET ' + "https://${registry}/v2/${product}/tags/list")
            def json = readJSON text: allTags
            def tags = json.tags.minus(["latest"])

            // Now sort the tags
            def sortedTags = []
            for (String tag in tags) {
              if (tag.isInteger()) {
                sortedTags.add(tag as Integer);
              } else {
                echo "[Warning] Found tag that is not an integer: ${tag}"
              }
            }
            sortedTags = sortedTags.sort();

            // Remove the number of tags we want to keep, use the rest to remove the images from the registry
            if (sortedTags.size() > versionsToKeep) {
              for (int i in 1..versionsToKeep) {
                sortedTags.pop()
              }
              
              for (Integer tag in sortedTags) {
                // Pulling the image to deprecate to get the sha/digest, removed afterwards
                def digest = sh(returnStdout: true, script: "docker pull ${registry}/${product}:${tag} | grep \"Digest: \" | awk \'{print \$2}\'")
                sh "docker rmi ${registry}/${product}:${tag}"

                if ((digest != null) && (digest.length() != 0)) {
                  echo "Deprecating version ${tag}..."
                  echo "Digest of ${tag}: ${digest}"
                  sh('curl -u $USERPASS -k --request DELETE ' + "https://${registry}/v2/${product}/manifests/${digest}")
                }
              }
            }
          }
        }
      }
      
      stage('Clean Local Docker Resources') {
        /**
          --filter "until 336h": Don't consider Docker resources unless they are at least 2 weeks old (336 hours)
          -f: force prune, needed to avoid prompting the user
        **/
        sh(returnStdout: false, script: "docker system prune --filter \"until=336h\" -f")
      }
    }

    office365ConnectorSend (
      status: "Completed",
      color: "00FF00",
      webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}",
      message: "New images built and pushed!",
      factDefinitions: [[name: "OpenCTI", template: "docker pull ${image}"]]
    )
  } catch(Exception ex) {
    office365ConnectorSend status: "Failed", webhookUrl: "${env.TEAMS_DOCKER_HOOK_URL}"
    throw ex;
  }
}
