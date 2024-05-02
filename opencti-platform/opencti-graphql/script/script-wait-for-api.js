import fetch from 'node-fetch';
import conf, { logApp } from '../src/config/conf';

const API_URI = `http://localhost:${conf.get('app:port')}`;

const MAX_ATTEMPTS = 30;
const DELAY_BETWEEN_ATTEMPTS = 5000;

const checkApiAvailability = async () => {
  try {
    await fetch(`${API_URI}/health`, {});
    return true;
  } catch (e) {
    logApp.info('[WAIT-FOR-API] API unavailable');
    return false;
  }
};

const waitForApi = async () => {
  const delay = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
  logApp.info('[WAIT-FOR-API] Start waiting for API');

  let available = false;
  let attempt = 0;
  while (!available && attempt < MAX_ATTEMPTS) {
    if (attempt > 0) {
      await delay(DELAY_BETWEEN_ATTEMPTS);
    }
    attempt += 1;
    available = await checkApiAvailability();
  }
  if (!available) {
    logApp.error('[WAIT-FOR-API] API not reachable');
    process.exit(1);
  }
  logApp.info('[WAIT-FOR-API] Success - API reachable');
};

// noinspection JSIgnoredPromiseFromCall
waitForApi();
