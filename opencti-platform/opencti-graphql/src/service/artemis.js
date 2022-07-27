import conf from '../config/conf.js';
import fetch from 'node-fetch';

const host = conf.get('artemis:rest:hostname');
const port = conf.get('artemis:rest:port');
const username = conf.get('artemis:rest:username');
const password = conf.get('artemis:rest:passcode');

export const artemisAlive = async () => {
  let credentials = Buffer.from(username + ":" + password).toString('base64');
  let server_url = `https://${host}:${port}/rest/`;

  try {
    let url = server_url + 'queues/cyio.tasks.export'
    let topicResponse = await fetch(url, {
      method: 'get',
      headers: {
        'Authorization': 'Basic ' + credentials
      },
    });
    if (!topicResponse.ok) throw new HTTPResponseError(topicResponse);

    // get the msg-create URL from the header so that the post can be performed
    if (topicResponse.headers.get('msg-create') != null ) return true;
  } catch (e) {
    return false;
  }
};
