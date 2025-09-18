import { IngestionConnectorsQuery$data } from '@components/data/IngestionCatalog/__generated__/IngestionConnectorsQuery.graphql';

type Connector = NonNullable<IngestionConnectorsQuery$data['connectors']>[number];

const createDeploymentCountMap = (connectors: readonly Connector[]) => {
  const deploymentCountMap = new Map<string, number>();

  const hasManagerContractImage = (connector: Connector): connector is Connector & { manager_contract_image: string } => {
    return connector.manager_contract_image != null;
  };

  const connectorsWithManagerContract = connectors.filter(hasManagerContractImage);

  for (const connector of connectorsWithManagerContract) {
    const containerType = connector.manager_contract_image.split(':')[0];
    const counter = deploymentCountMap.get(containerType) ?? 0;
    deploymentCountMap.set(containerType, counter + 1);
  }

  return deploymentCountMap;
};

export default createDeploymentCountMap;
