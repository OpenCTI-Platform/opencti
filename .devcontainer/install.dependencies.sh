echo -e "\n\nInstalling OpenCTI Frontend dependencies ...\n"
cd /opencti/opencti-platform/opencti-front/
yarn install

echo -e "\n\nInstalling OpenCTI GraphQL dependencies ...\n"
cd /opencti/opencti-platform/opencti-graphql/
yarn install
yarn install:python

echo -e "\n\nInstalling the Python workspace (pycti, worker, platform runtime) ...\n"
cd /opencti
uv sync --locked --all-packages