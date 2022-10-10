import { PythonShell } from 'python-shell';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
// import * as nodecallspython from 'node-calls-python';
import { DEV_MODE, logApp } from '../config/conf';
import { UnknownError } from '../config/errors';
import { telemetry } from '../config/tracing';

/*
// Importing python runtime scripts
const py = nodecallspython.interpreter;
const pyCheckIndicator = py.importSync('./src/python/runtime/check_indicator.py');
const CHECK_INDICATOR_SCRIPT = { fn: 'check_indicator', py: pyCheckIndicator };

const pyCreatePattern = py.importSync('./src/python/runtime/stix2_create_pattern.py');
const CREATE_PATTERN_SCRIPT = { fn: 'stix2_create_pattern', py: pyCreatePattern };
*/

export const execTestingPython = async (context, user, scriptPath, scriptName, args, stopCondition) => {
  const execPythonTestingProcessFn = () => {
    return new Promise((resolve, reject) => {
      const messages = [];
      const options = {
        mode: 'text',
        pythonPath: DEV_MODE ? 'python' : 'python3',
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
        logApp.info(`[stderr] ${stderr}`);
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
      throw UnknownError(`[BRIDGE] execPythonTesting error > ${err.message}`, { detail: err.message });
    });
  };
  return telemetry(context, user, `PYTHON ${scriptName}`, {
    [SemanticAttributes.DB_NAME]: 'python_testing_engine',
  }, execPythonTestingProcessFn);
};
/*
export const execNativePython = async (context, user, script, ...args) => {
  const execNativePythonFn = async () => {
    try {
      const result = py.callSync(script.py, script.fn, ...args);
      if (result.status === 'success') {
        return result.data;
      }
      throw UnknownError('[BRIDGE] execNativePython error', { detail: result.data });
    } catch (err) {
      throw UnknownError(`[BRIDGE] execNativePython error > ${err.message}`, { detail: err.message });
    }
  };
  return telemetry(context, user, `PYTHON ${script.fn}`, {
    [SemanticAttributes.DB_NAME]: 'python_runtime_engine',
  }, execNativePythonFn);
};

export const createStixPattern = async (context, user, observableType, observableValue) => {
  return execNativePython(context, user, CREATE_PATTERN_SCRIPT, observableType, observableValue).catch((err) => {
    logApp.warn(`[BRIDGE] createStixPattern error > ${err.message}`);
    return null;
  });
};
export const checkIndicatorSyntax = async (context, user, patternType, indicatorValue) => {
  return execNativePython(context, user, CHECK_INDICATOR_SCRIPT, patternType, indicatorValue).catch((err) => {
    logApp.warn(`[BRIDGE] checkIndicatorSyntax error > ${err.message}`);
    return null;
  });
};
export const checkPythonAvailability = async (context, user) => {
  return execNativePython(context, user, CREATE_PATTERN_SCRIPT, 'check', 'health');
};
*/

export const createStixPattern = async (context, user, observableType, observableValue) => {
  try {
    const result = await execTestingPython(
      context,
      user,
      './src/python/runtime',
      'stix2_create_pattern.py',
      [observableType, observableValue]
    );
    return result.data;
  } catch (err) {
    logApp.warn(`[BRIDGE] createStixPattern error > ${err.message}`);
    return null;
  }
};
export const checkIndicatorSyntax = async (context, user, patternType, indicatorValue) => {
  try {
    const result = await execTestingPython(
      context,
      user,
      './src/python/runtime',
      'check_indicator.py',
      [patternType, indicatorValue]
    );
    return result.data;
  } catch (err) {
    logApp.warn(`[BRIDGE] extractObservables error > ${err.message}`);
    return null;
  }
};
export const checkPythonAvailability = (context, user) => {
  return execTestingPython(context, user, './src/python/runtime', 'stix2_create_pattern.py', ['check', 'health']);
};
