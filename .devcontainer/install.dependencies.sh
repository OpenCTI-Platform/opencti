echo -e "\n\nInstalling OpenCTI Frontend dependencies ...\n"
cd /opencti/opencti-platform/opencti-front/
yarn install

echo -e "\n\nInstalling OpenCTI GraphQL dependencies ...\n"
cd /opencti/opencti-platform/opencti-graphql/
yarn install
yarn install:python

echo -e "\n\nInstalling OpenCTI Python client ...\n"
pip install 'git+https://github.com/OpenCTI-Platform/client-python@master'