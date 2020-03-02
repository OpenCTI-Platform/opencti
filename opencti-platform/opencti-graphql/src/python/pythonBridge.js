import { PythonShell } from 'python-shell';
import { logger } from '../config/conf';

const isJSON = str => {
  const prepareStr = str
    .replace(/\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})/g, '@')
    .replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?/g, ']')
    .replace(/(?:^|:|,)(?:\s*\[)+/g, '');
  return /^[\],:{}\s]*$/.test(prepareStr);
};

export const execPython3 = async (scriptPath, scriptName, args) => {
  try {
    return new Promise((resolve, reject) => {
      const options = {
        mode: 'text',
        pythonPath: 'python3',
        scriptPath,
        args
      };
      const shell = new PythonShell(scriptName, options);
      // Messaging is used to get data out of the python process
      let jsonResult = { status: 'success' };
      shell.on('message', message => {
        jsonResult = JSON.parse(isJSON(message) ? message : { status: 'error', message });
      });
      shell.on('stderr', stderr => {
        logger.info(`[API-PYTHON] > ${stderr}`);
      });
      shell.end(err => {
        if (err) reject(err);
        if (jsonResult.status !== 'success') reject(jsonResult);
        resolve(jsonResult);
      });
    });
  } catch (err) {
    throw new Error(`Python3 is missing or script not found: ${err}`);
  }
};

export const checkPythonStix2 = async () => {
  try {
    const result = await execPython3('./src/python', 'stix2_create_pattern.py', ['check', 'health']);
    if (result.status !== 'success') {
      throw new Error('Python3 with STIX2 module is missing');
    }
    return result;
  } catch (err) {
    throw new Error(`Python3 check fail ${err}`);
  }
};

export const createStixPattern = async (observableType, observableValue) => {
  try {
    const result = await execPython3('./src/python', 'stix2_create_pattern.py', [observableType, observableValue]);
    if (result.status === 'success') {
      return result.data;
    }
    return null;
  } catch (err) {
    logger.error('[Python3] createStixPattern error > ', err);
    return null;
  }
};

export const extractObservables = async pattern => {
  try {
    const result = await execPython3('./src/python', 'stix2_extract_observables.py', [pattern]);
    if (result.status === 'success') {
      return result.data;
    }
    return null;
  } catch (err) {
    logger.error('[Python3] extractObservables error > ', err);
    return null;
  }
};
