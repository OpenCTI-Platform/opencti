echo -e "\n\nInstalling the JavaScript workspace (front, GraphQL API, custom ESLint rules) ...\n"
cd /opencti
yarn install

echo -e "\n\nInstalling OpenCTI GraphQL Python dependencies ...\n"
cd /opencti/opencti-platform/opencti-graphql/
yarn install:python

echo -e "\n\nInstalling OpenCTI Python client ...\n"
cd /opencti/client-python
pip install -r requirements.txt