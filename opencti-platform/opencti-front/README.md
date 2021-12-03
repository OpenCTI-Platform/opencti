# OpenCTI Front

## Development

### Environment


Development of the frontend code will require on of two setups:
* Run the `opencti-graphql` manually along with the needed docker dependencies
* Connect to the remote develop server and only have to run the React client

Regardless of either setup, the API environment variables is always going to be required:
* REACT_APP_API_URL
  * Get access to our VSAC API for related features (contact DarkLight engineer)

#### Connecting to Remote Server
To connect to the remote server, you will need a certificate and key provided by DarkLight and include some environment variables when running the React client.

Environment Variables:
* REACT_APP_GRAPHQL_HOST
  * The remote server host (contact a DarkLight engineer)
* HOST=cyio-localhost.darklight.ai
  * Forces the React client to run at this domain which points to 127.0.0.1 (localhost)
* HTTPS=true
  * Starts up the client in HTTPS/TLS mode
* SSL_CRT_FILE=\<path to certificate file\>
  * Provides the certificate for HTTPS/TLS
* SSL_KEY_FILE=\<path to key file\>
  * Provides the key for HTTPS/TLS

#### Certificates
To get the needed certificates, contact a DarkLight admin or senior engineer.

You will need to add the `crt` or `ca` file as trusted certs on your local system. For windows follow these instructions:

* [How Do I Add Certificates to the Trusted Root Certification Authorities Store for a Local Computer? (force.com)](https://asu.secure.force.com/kb/articles/FAQ/How-Do-I-Add-Certificates-to-the-Trusted-Root-Certification-Authorities-Store-for-a-Local-Computer)

For Linux/MacOS:

* [How to add root certificate to Mac OS X](https://www.eduhk.hk/ocio/content/faq-how-add-root-certificate-mac-os-x)