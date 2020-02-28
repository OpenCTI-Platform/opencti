import { PythonShell } from 'python-shell';
import { logger } from '../config/conf';

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
      shell.on('message', message => {
        try {
          resolve(JSON.parse(message));
        } catch (e) {
          // Result should be json, if not consider it as an error
          reject(e);
        }
      });
      shell.on('stderr', stderr => {
        logger.info(`[API-PYTHON] > ${stderr}`);
      });
      shell.end((err, code) => {
        if (err) reject(err);
        resolve(code);
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
  } catch (err) {
    throw new Error('Python3 with STIX2 module is missing');
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
