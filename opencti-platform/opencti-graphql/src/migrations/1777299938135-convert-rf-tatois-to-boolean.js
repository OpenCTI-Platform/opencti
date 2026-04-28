import { logMigration } from '../config/conf';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { FilterMode } from '../generated/graphql';
import { fullEntitiesList } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { patchAttribute } from '../database/middleware';

const message = '[MIGRATION] recorded future managed connector';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const allManagedRecordedFutureArgs = {
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['manager_contract_image'], values: ['opencti/connector-recorded-future'] }], filterGroups: [] },
  };
  const allManagedRecordedFuture = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR], allManagedRecordedFutureArgs);
  logMigration.info(`${message} > ${allManagedRecordedFuture.length} Managed recorded future connector to evaluate`);

  for (let i = 0; i < allManagedRecordedFuture.length; i++) {
    const currentConnector = allManagedRecordedFuture[i];
    if (currentConnector.manager_contract_configuration) {
      const rfEnvvar = currentConnector.manager_contract_configuration.find((item) => item.key === 'RECORDED_FUTURE_TA_TO_INTRUSION_SET');
      if (rfEnvvar.value !== 'true' && rfEnvvar.value !== 'false') {
        const newValueForRF_taToIs = rfEnvvar.value.length > 0;
        logMigration.info(`${message} > connectorId:${currentConnector.id} will have RECORDED_FUTURE_TA_TO_INTRUSION_SET rewrite as ${newValueForRF_taToIs}`);
        const newContract = currentConnector.manager_contract_configuration.filter((item) => item.key !== 'RECORDED_FUTURE_TA_TO_INTRUSION_SET');
        newContract.push({ key: 'RECORDED_FUTURE_TA_TO_INTRUSION_SET', value: `${newValueForRF_taToIs}` });
        const patch = {
          manager_contract_configuration: newContract,
        };
        await patchAttribute(context, SYSTEM_USER, currentConnector.id, ENTITY_TYPE_CONNECTOR, patch);
        logMigration.info(`${message} > connectorId:${currentConnector.id} RECORDED_FUTURE_TA_TO_INTRUSION_SET rewrite as ${newValueForRF_taToIs}, done.`);
      }
    }
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
