echo -e "\n\nInstalling OpenCTI Frontend dependencies ...\n"
cd /opencti/opencti-platform/opencti-front/
yarn install

echo -e "\n\nInstalling OpenCTI GraphQL dependencies ...\n"
cd /opencti/opencti-platform/opencti-graphql/
yarn install
yarn install:python

echo -e "\n\nInstalling OpenCTI Python client ...\n"
cd /opencti/client-python
pip install -r requirements.txt