import fetch from 'node-fetch';
import https from 'node:https';
import { readFileSync } from 'fs';
import conf, { logApp } from '../config/conf';

const host = conf.get('artemis:rest:hostname');
const port = conf.get('artemis:rest:port');
const username = conf.get('artemis:rest:username');
const password = conf.get('artemis:rest:passcode');

const key = conf.get('app:https_cert:key');
const crt = conf.get('app:https_cert:crt');

export const artemisAlive = async () => {
  const credentials = Buffer.from(`${username}:${password}`).toString('base64');
  const server_url = `https://${host}:${port}/rest/`;

  try {
    const url = `${server_url}queues/cyio.tasks.export`;
    let httpsAgent = null;

    if (key || crt) {
      httpsAgent = new https.Agent({
        key: key ? readFileSync(key) : null,
        cert: crt ? readFileSync(crt) : null,
      });
    }

    const topicResponse = await fetch(url, {
      agent: httpsAgent,
      method: 'get',
      headers: {
        Authorization: `Basic ${credentials}`,
      },
    });

    if (!topicResponse.ok) {
      logApp.error('[INIT] Failed to communicate with Artemis');
      return false;
    }

    // get the msg-create URL from the header so that the post can be performed
    if (topicResponse.headers.get('msg-create') != null) return true;
  } catch (e) {
    return false;
  }
};
