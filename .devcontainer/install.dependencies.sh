echo -e "\n\nInstalling the JavaScript workspace (front, GraphQL API, custom ESLint rules) ...\n"
cd /opencti
yarn install

echo -e "\n\nInstalling OpenCTI GraphQL Python dependencies ...\n"
cd /opencti/opencti-platform/opencti-graphql/
yarn install:python

echo -e "\n\nInstalling the Python workspace (pycti, worker, platform runtime) ...\n"
cd /opencti
uv sync --locked --all-packages