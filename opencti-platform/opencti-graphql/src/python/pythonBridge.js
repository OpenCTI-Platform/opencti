import { PythonShell } from 'python-shell';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { DEV_MODE, logApp } from '../config/conf';
import { ConfigurationError } from '../config/errors';
import { telemetry } from '../config/tracing';

export const execPython3 = async (context, user, scriptPath, scriptName, args, stopCondition) => {
  const execPython3Fn = () => {
    return new Promise((resolve, reject) => {
      const messages = [];
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
        messages.push(stderr);
        /* istanbul ignore if */
        if (DEV_MODE && stderr.startsWith('ERROR:')) {
          jsonResult = { status: 'error', message: stderr };
          shell.kill();
        }
        if (stopCondition && stopCondition(stderr, messages)) {
          shell.kill();
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
    }).catch((err) => {
      /* istanbul ignore next */
      throw ConfigurationError('Python3 is missing or script not found', { detail: err.message });
    });
  };
  return telemetry(context, user, `PYTHON ${scriptName}`, {
    [SemanticAttributes.DB_NAME]: 'python_engine',
    [SemanticAttributes.DB_OPERATION]: 'listing',
  }, execPython3Fn);
};

export const checkPythonStix2 = (context, user) => {
  return execPython3(context, user, './src/python', 'stix2_create_pattern.py', ['check', 'health']);
};

export const createStixPattern = async (context, user, observableType, observableValue) => {
  try {
    const result = await execPython3(context, user, './src/python', 'stix2_create_pattern.py', [observableType, observableValue]);
    return result.data;
  } catch (err) {
    return null;
  }
};

export const checkIndicatorSyntax = async (context, user, patternType, indicatorValue) => {
  try {
    const result = await execPython3(context, user, './src/python', 'check_indicator.py', [patternType, indicatorValue]);
    return result.data;
  } catch (err) {
    logApp.warn(`[BRIDGE] extractObservables error > ${err.message}`);
    return null;
  }
};

export const executePython = async (context, user, path, file, args, stopCondition) => {
  try {
    const result = await execPython3(context, user, path, file, args, stopCondition);
    return result.data;
  } catch (err) {
    logApp.warn(`[BRIDGE] executePython error > ${err.message}`);
    return null;
  }
};
