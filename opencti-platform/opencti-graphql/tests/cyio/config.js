const axios = require('axios');
const https = require('https');
require('dotenv').config();

const buildHeaders = () => {
  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-Cyio-Client': process.env.TESTING_CLIENT_ID,
  };

  return headers;
};

export default async function submitOperation(operation, vars, res) {
  return new Promise((resolve,reject) => {
    const data = JSON.stringify({
      query: operation,
      variables: vars,
    });
    const config = {
      method: 'post',
      url: `${process.env.TESTING_GRAPHQL_HOST}/graphql`,
      headers: buildHeaders(),
      httpsAgent: new https.Agent({
        rejectUnauthorized: false,
      }),
      data,
    };

    axios(config)
      .then(function resp(response) {
        resolve(response.data);
      })
      .catch(function err(error) {
        if(null != res) {
          res.status(404).json(error);
        } else {
          reject(error)   //TODO: afaik res never used so instead reject every time like so?
        }
      });
  });
}
