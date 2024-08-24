import { v5 as uuidv5 } from 'uuid';
import type { AuthContext } from '../../types/user';
import { connectorDelete, registerConnector } from '../../domain/connector';
import { SYSTEM_USER } from '../../utils/access';
import { OPENCTI_NAMESPACE } from '../../schema/general';
import { ConnectorType } from '../../generated/graphql';

export const registerConnectorForIngestion = async (context: AuthContext, type: string, ingestion: any) => {
  // Create the representing connector
  await registerConnector(context, SYSTEM_USER, {
    id: uuidv5(ingestion.id, OPENCTI_NAMESPACE),
    name: `[${type}] ${ingestion.name}`,
    type: ConnectorType.ExternalImport,
    auto: true,
    scope: ['application/stix+json;version=2.1'],
    only_contextual: false,
    playbook_compatible: false
  }, {
    active: ingestion.ingestion_running,
    built_in: true
  });
};

export const unregisterConnectorForIngestion = async (context: AuthContext, ingestion: any) => {
  await connectorDelete(context, SYSTEM_USER, uuidv5(ingestion.id, OPENCTI_NAMESPACE));
};
