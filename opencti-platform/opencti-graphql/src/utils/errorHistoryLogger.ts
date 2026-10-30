import { FORBIDDEN_ACCESS, AUTH_ERRORS, FUNCTIONAL_ERRORS, TECHNICAL_ERRORS } from '../config/errors';
import { ENTITY_TYPE_ACTIVITY } from '../schema/internalObject';

const isValidError = (errCode: string, httpStatus: any) => {
    let isValid = true;
    if (AUTH_ERRORS.includes(errCode) || errCode === FORBIDDEN_ACCESS) {
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

// TODO create a function that handels writing to the DB
const errorPayload = (userContext: any, errorContext: any) => {
    const timestamp = new Date().toISOString();
    const timestampMs = Date.now();
    const payloadId = `${timestampMs}-0`;
    const errCode = errorContext?.extensions?.code || 'UNKNOWN';
    const errName = errorContext?.status_type || errorContext?.extensions?.code || 'UNKNOWN';
    const errMsg = `[${errCode}] MSG: ${errorContext?.message}`;
    const rawErrData = JSON.stringify(errorContext);

    const errScope = getErrorType(errCode);

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

export const logUserActionErrorsToHistory = (error: any, user: any) => {
    setImmediate(async () => {
        const rawErr = error;
        const errCode = rawErr?.extensions?.code;
        const httpStatus = rawErr?.extensions?.http_status;
        // printTermMsg(user, 'RAW USR', 'cyn');

        if (!isValidError(errCode, httpStatus)) {
            return;
        }

        if (error.category === 'DATABASE_ERROR' || error.message?.includes('opencti_history')) {
            return;
        }

        const userContext = user;

        try {
            const { elIndex } = await import('../database/engine.js');
            const { INDEX_HISTORY } = await import('../database/utils');
            const errorHistoryPayload = errorPayload(userContext, rawErr);

            await elIndex(INDEX_HISTORY, errorHistoryPayload);
        } catch (e) {
            process.stderr.write('[ErrorHistoryTransport Fail] ${String(dbWriteFail.message)}\n');
        }
    });
};
