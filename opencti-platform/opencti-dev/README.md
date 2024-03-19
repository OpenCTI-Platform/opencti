# Development tools in this folder

- **Backend start dev**: 
  - start one instance of the backend platform on http://localhost:4000
  - requires a development.json file in `opencti-graphql/config` folder or environment variables (except for port)
- **Backend start cluster**: start a second instance of opencti, using port 4001 on http://localhost:4001
  - requires a cluster.json file in `opencti-graphql/config` folder or environment variables (except for port)
- **Frontend start dev**:
    - start one instance of the frontend with port `3000` using backend on http://localhost:4000
- **Frontend start cluster**:
  - start a second instance of the frontend with port `3001` using backend on http://localhost:4001

For day to day development you can only start the "dev" pair (`Backend start dev` and `Frontend start dev`), if you want to have a cluster locally, add the "cluster" pair.