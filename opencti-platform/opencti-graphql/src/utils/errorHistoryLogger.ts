import { v4 as uuidv4 } from 'uuid';
import { logApp } from '../config/conf';
import { AUTH_ERRORS, FUNCTIONAL_ERRORS, PASSWORD_CHANGE_THROTTLED, PASSWORD_RESET_EXPIRED, PASSWORD_REUSED, TECHNICAL_ERRORS, VALIDATION_ERROR } from '../config/errors';
import { ENTITY_TYPE_ACTIVITY } from '../schema/internalObject';
import type { RequestSensitivity } from './log-redaction';

const isValidError = (errCode: string, httpStatus: any) => {
  const blackListErrorCodes = [...AUTH_ERRORS, PASSWORD_REUSED, PASSWORD_CHANGE_THROTTLED, PASSWORD_RESET_EXPIRED];
  let isValid = true;
  if (blackListErrorCodes.includes(errCode) || errCode === VALIDATION_ERROR) {
    isValid = false;
  } else if (httpStatus === 401) {
    isValid = false;
  }
  return isValid;
};

export const ERROR_TYPES = ['auth_error', 'graphql_error', 'functional_error', 'technical_error', 'user_action_error'];

const getErrorType = (errCode: string) => {
  let errType = 'user_action_error';
  if (FUNCTIONAL_ERRORS.includes(errCode)) {
    errType = 'functional_error';
  }

  if (TECHNICAL_ERRORS.includes(errCode)) {
    errType = 'technical_error';
  }
  if (AUTH_ERRORS.includes(errCode)) {
    errType = 'auth_error';
  }

  if (errCode.includes('graphql'.toUpperCase())) {
    errType = 'graphql_error';
  }

  return errType;
};

const errorPayload = (userContext: any, errorContext: any, isSensitive: boolean) => {
  const timestamp = new Date().toISOString();
  const timestampMs = Date.now();
  const payloadId = `${timestampMs}-${uuidv4()}`;
  const errCode = errorContext?.extensions?.code || 'UNKNOWN';
  const errName = errorContext?.status_type || errorContext?.extensions?.code || 'UNKNOWN';

  const errScope = getErrorType(errCode);
  let msg;
  let data;
  if (isSensitive) {
    msg = '[REDACTED] Error message contains sensitive data.';
    data = msg;
  } else {
    msg = errorContext?.message;
    data = JSON.stringify(errorContext); ;
  }
  const errMsg = `[${errCode}] MSG: ${msg}`;
  const rawErrData = data;

  const contextData = {
    message: errMsg,
  };

  const errData = {
    name: errName,
    code: errCode,
    message: errMsg,
    raw_data: rawErrData,
  };

  const payload = {
    internal_id: payloadId,
    id: payloadId,
    timestamp: timestamp,
    entity_type: ENTITY_TYPE_ACTIVITY,
    event_scope: errScope,
    event_type: 'error',
    event_status: 'error',
    error_data: errData,
    user_id: userContext.id,
    context_data: contextData,
  };
  return payload;
};

export const logUserActionErrorsToHistory = (error: any, user: any, sensitivity: RequestSensitivity) => {
  setImmediate(async () => {
    const rawErr = error;
    const errCode = rawErr?.extensions?.code;
    const httpStatus = rawErr?.extensions?.data?.http_status;

    if (!isValidError(errCode, httpStatus)) {
      return;
    }

    if (errCode === 'DATABASE_ERROR' || error.message?.includes('opencti_history')) {
      return;
    }

    const userContext = user;

    try {
      const { elIndex } = await import('../database/engine.js');
      const { INDEX_HISTORY } = await import('../database/utils');
      const errorHistoryPayload = errorPayload(userContext, rawErr, sensitivity.hideQuery);

      await elIndex(INDEX_HISTORY, errorHistoryPayload);
    } catch (e) {
      logApp.error(`[Error History Logger] DB Error: ${e}`);
    }
  });
};
