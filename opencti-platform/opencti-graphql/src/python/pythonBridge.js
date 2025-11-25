import { PythonShell } from 'python-shell';
import { SEMATTRS_DB_NAME } from '@opentelemetry/semantic-conventions';
import * as nodecallspython from 'node-calls-python';
import nconf from 'nconf';
import { DEV_MODE, logApp } from '../config/conf';
import { UnknownError, UnsupportedError } from '../config/errors';
import { telemetry } from '../config/tracing';
import { cleanupIndicatorPattern, STIX_PATTERN_TYPE } from '../utils/syntax';
import { isEmptyField, isNotEmptyField } from '../database/utils';

const PYTHON_EXECUTOR = nconf.get('app:python_execution') ?? 'native';
const PYTHON_VENV = nconf.get('app:python_execution_venv');
const USE_NATIVE_EXEC = PYTHON_EXECUTOR === 'native';
const SUPPORTED_CHECKED_PATTERN_TYPES = ['stix', 'yara', 'sigma', 'snort', 'suricata', 'eql'];

// Importing python runtime scripts
const py = nodecallspython.interpreter;
// In a venv is available import the site-packages
if (isNotEmptyField(PYTHON_VENV)) {
  py.addImportPath(PYTHON_VENV);
}
const pyCheckIndicator = py.importSync('./src/python/runtime/check_indicator.py');
const CHECK_INDICATOR_SCRIPT = { fn: 'check_indicator', py: pyCheckIndicator };

const pyCreatePattern = py.importSync('./src/python/runtime/stix2_create_pattern.py');
const CREATE_PATTERN_SCRIPT = { fn: 'stix2_create_pattern', py: pyCreatePattern };

// region child
export const execChildPython = async (context, user, scriptPath, scriptName, args, stopCondition) => {
  const execPythonTestingProcessFn = async () => {
    if (isEmptyField(scriptPath) || isEmptyField(scriptName)) {
      throw UnsupportedError('Cannot execute Python with empty script path or name');
    }
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
      let jsonResult = { status: 'success', messages };
      shell.on('message', (message) => {
        // to uncomment for debug if counters are failing
        // messages.push(message);
        /* v8 ignore next */
        try {
          jsonResult = JSON.parse(message);
        } catch (_e) {
          jsonResult = { status: 'error', message };
        }
      });
      shell.on('stderr', (stderr) => {
        logApp.error('[PYTHON BRIDGE] Error executing python', { stderr });
        messages.push(stderr);
        //* v8 ignore if */
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
          reject(UnknownError('Error python child execution', jsonResult));
        }
        resolve(jsonResult);
      });
    });
  };
  return telemetry(context, user, `PYTHON ${scriptName}`, {
    [SEMATTRS_DB_NAME]: 'python_testing_engine',
  }, execPythonTestingProcessFn);
};
const createChildStixPattern = async (context, user, observableType, observableValue) => {
  try {
    const result = await execChildPython(
      context,
      user,
      './src/python/runtime',
      'stix2_create_pattern.py',
      [observableType, observableValue]
    );
    return result.data;
  } catch (err) {
    logApp.warn('[BRIDGE] createChildStixPattern', { cause: err });
    return null;
  }
};
const checkChildIndicatorSyntax = async (context, user, patternType, indicatorValue) => {
  try {
    const result = await execChildPython(
      context,
      user,
      './src/python/runtime',
      'check_indicator.py',
      [patternType, indicatorValue]
    );
    return result.data;
  } catch (err) {
    logApp.warn('[BRIDGE] checkChildIndicatorSyntax', { cause: err });
    return null;
  }
};
const checkChildPythonAvailability = async (context, user) => {
  const result = await execChildPython(context, user, './src/python/runtime', 'stix2_create_pattern.py', ['check', 'health']);
  return result.data;
};
// endregion

// region native
const execNativePythonSync = (script, ...args) => {
  const result = py.callSync(script.py, script.fn, ...args);
  if (result.status === 'success') {
    return result.data;
  }
  throw UnknownError('[BRIDGE] execNativePython error', result);
};
const execNativePython = async (context, user, script, ...args) => {
  const execNativePythonFn = async () => {
    const result = py.callSync(script.py, script.fn, ...args);
    if (result.status === 'success') {
      return result.data;
    }
    throw UnknownError('[BRIDGE] execNativePython error', result);
  };
  return telemetry(context, user, `PYTHON ${script.fn}`, {
    [SEMATTRS_DB_NAME]: 'python_runtime_engine',
  }, execNativePythonFn);
};
const createNativeStixPattern = async (context, user, observableType, observableValue) => {
  return execNativePython(context, user, CREATE_PATTERN_SCRIPT, observableType, observableValue).catch((err) => {
    logApp.warn('[BRIDGE] createNativeStixPattern', { cause: err });
    return null;
  });
};
const checkNativeIndicatorSyntax = async (context, user, patternType, indicatorValue) => {
  return execNativePython(context, user, CHECK_INDICATOR_SCRIPT, patternType, indicatorValue).catch((err) => {
    logApp.warn('[BRIDGE] checkNativeIndicatorSyntax', { cause: err });
    return null;
  });
};
const checkNativePythonAvailability = async (context, user) => {
  return createStixPattern(context, user, 'Text', 'test');
};
// endregion

// region functions
export const createStixPatternSync = (observableType, observableValue) => {
  const stixPattern = execNativePythonSync(CREATE_PATTERN_SCRIPT, observableType, observableValue);
  return cleanupIndicatorPattern(STIX_PATTERN_TYPE, stixPattern);
};
export const createStixPattern = async (context, user, observableType, observableValue) => {
  const stixPattern = await (USE_NATIVE_EXEC ? createNativeStixPattern(context, user, observableType, observableValue)
    : createChildStixPattern(context, user, observableType, observableValue));
  return cleanupIndicatorPattern(STIX_PATTERN_TYPE, stixPattern);
};
export const checkIndicatorSyntax = async (context, user, patternType, indicatorValue) => {
  if (!SUPPORTED_CHECKED_PATTERN_TYPES.includes(patternType)) {
    return true;
  }
  if (USE_NATIVE_EXEC) {
    return checkNativeIndicatorSyntax(context, user, patternType, indicatorValue);
  }
  return checkChildIndicatorSyntax(context, user, patternType, indicatorValue);
};
export const checkPythonAvailability = async (context, user) => {
  if (USE_NATIVE_EXEC) {
    return checkNativePythonAvailability(context, user);
  }
  return checkChildPythonAvailability(context, user);
};
// endregion
