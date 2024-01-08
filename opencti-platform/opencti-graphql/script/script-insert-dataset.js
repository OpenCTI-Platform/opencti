import fetch from 'node-fetch';
import '../src/modules/index';
import { executionContext } from '../src/utils/access';
import { checkPythonAvailability, execChildPython } from '../src/python/pythonBridge';
import conf, { logApp } from '../src/config/conf';
import httpServer from '../src/http/httpServer';
import cacheManager from '../src/manager/cacheManager';

const ADMIN_USER = { id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f' };
const API_URI = `http://localhost:${conf.get('app:port')}`;
const API_TOKEN = conf.get('app:admin:token');
const PYTHON_PATH = './src/python/testing';
const sample1 = [API_URI, API_TOKEN, './tests/data/DATA-TEST-STIX2_v2.json'];
const sample2 = [API_URI, API_TOKEN, './tests/data/poisonivy.json'];

const scriptInsertDataset = async () => {
  const executeContext = executionContext('insert-dataset');
  const startingHandler = await getStartingHandler();
  try {
    // Init the httpServer if needed
    await startingHandler.start();
    // Check python availability
    await checkPythonAvailability(executeContext, ADMIN_USER);
    // Insert dataset
    await execChildPython(executeContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', sample1);
    await execChildPython(executeContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', sample2);
    logApp.info('[OPENCTI] Dataset insertion succeeded');
  } catch (e) {
    logApp.error('[OPENCTI] Dataset insertion failed', { error: e });
  } finally {
    // Stop the httpServer if needed
    await startingHandler.shutdown();
  }
};

const getStartingHandler = () => {
  const manualStartHandler = {
    start: () => {
      logApp.info('[OPENCTI] The httpServer is already launched');
    },
    shutdown: () => {
      process.exit();
    }
  };
  const autoStartHandler = {
    start: async () => {
      logApp.info('[OPENCTI] The httpServer is autostarted');
      await cacheManager.start();
      await httpServer.start();
    },
    shutdown: async () => {
      await cacheManager.shutdown();
      await httpServer.shutdown();
      process.exit();
    }
  };
  return fetch(API_URI, {}).then(() => manualStartHandler).catch(() => autoStartHandler);
};

// noinspection JSIgnoredPromiseFromCall
scriptInsertDataset();
