import { connectors } from '../database/repository';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { logApp } from '../config/conf';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Rewriting stream connector erroneous state');
  const connectorsList = await connectors(context, SYSTEM_USER);
  await Promise.all(connectorsList.map((connector) => {
    try {
      const state = connector.connector_state;
      const decodedState = JSON.parse(state);
      if (decodedState.start_from && decodedState.start_from.includes('-0-0')) {
        decodedState.start_from = decodedState.start_from.replace('-0-0', '-0');
        const updatePatch = { connector_state: JSON.stringify(decodedState) };
        return patchAttribute(context, SYSTEM_USER, connector.id, ENTITY_TYPE_CONNECTOR, updatePatch);
      }
      // Not necessary to migrate
      return Promise.resolve(true);
    } catch (_e) {
      // Likely a null or empty state
      return Promise.resolve(true);
    }
  }));
  logApp.info('[MIGRATION] End rewriting stream connector erroneous state');
  next();
};

export const down = async (next) => {
  next();
};
