import { PythonShell } from 'python-shell';
import { DEV_MODE, logApp } from '../config/conf';
import { ConfigurationError } from '../config/errors';

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
        logApp.info(`[BRIDGE] ${stderr}`);
        /* istanbul ignore if */
        if (DEV_MODE && stderr.startsWith('ERROR:')) {
          jsonResult = { status: 'error', message: stderr };
          shell.terminate();
        }
      });
      shell.end((err) => {
        if (err) {
          reject(err);
          return;
        }
        if (jsonResult.status !== 'success') {
          reject(jsonResult);
          return;
        }
        resolve(jsonResult);
      });
    });
  } catch (err) {
    /* istanbul ignore next */
    throw ConfigurationError(`Python3 is missing or script not found`, { detail: err.message });
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
    logApp.warn(`[BRIDGE] createStixPattern error > ${err.message}`);
    return null;
  }
};

export const checkIndicatorSyntax = async (patternType, indicatorValue) => {
  try {
    const result = await execPython3('./src/python', 'check_indicator.py', [patternType, indicatorValue]);
    return result.data;
  } catch (err) {
    logApp.warn(`[BRIDGE] extractObservables error > ${err.message}`);
    return null;
  }
};
