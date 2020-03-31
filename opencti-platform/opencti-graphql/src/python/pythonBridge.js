import { PythonShell } from 'python-shell';
import { DEV_MODE, logger } from '../config/conf';

export const execPython3 = async (scriptPath, scriptName, args) => {
  try {
    return new Promise((resolve, reject) => {
      const options = {
        mode: 'text',
        pythonPath: 'python3',
        scriptPath,
        args,
      };
      const shell = new PythonShell(scriptName, options);
      // Messaging is used to get data out of the python process
      let jsonResult = { status: 'success' };
      shell.on('message', (message) => {
        /* istanbul ignore next */
        try {
          jsonResult = JSON.parse(message);
        } catch (e) {
          jsonResult = { status: 'error', message };
        }
      });
      shell.on('stderr', (stderr) => {
        logger.info(`[API-PYTHON] > ${stderr}`);
        /* istanbul ignore if */
        if (DEV_MODE && stderr.startsWith('ERROR:')) {
          jsonResult = { status: 'error', message: stderr };
          shell.terminate();
        }
      });
      shell.end((err) => {
        if (err) reject(err);
        if (jsonResult.status !== 'success') reject(jsonResult);
        resolve(jsonResult);
      });
    });
  } catch (err) {
    /* istanbul ignore next */
    throw new Error(`Python3 is missing or script not found: ${err.message}`);
  }
};

export const checkPythonStix2 = () => {
  return execPython3('./src/python', 'stix2_create_pattern.py', ['check', 'health']);
};

export const createStixPattern = async (observableType, observableValue) => {
  try {
    const result = await execPython3('./src/python', 'stix2_create_pattern.py', [observableType, observableValue]);
    return result.data;
  } catch (err) {
    logger.warn(`[Python3] createStixPattern error > ${err.message}`);
    return null;
  }
};

export const extractObservables = async (pattern) => {
  try {
    const result = await execPython3('./src/python', 'stix2_extract_observables.py', [pattern]);
    return result.data;
  } catch (err) {
    logger.warn(`[Python3] extractObservables error > ${err.message}`);
    return null;
  }
};
