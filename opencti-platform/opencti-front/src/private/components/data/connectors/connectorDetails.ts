import { IngestionConnector } from '@components/integrations/catalog/types';

interface DeployedConnectorDetailsInput {
  managerContractDefinition?: string | null;
  managerContractExcerpt?: { readonly slug?: string | null } | null;
}

// Version and slug of the catalog contract a managed connector was deployed with
export const getDeployedConnectorDetails = ({ managerContractDefinition, managerContractExcerpt }: DeployedConnectorDetailsInput) => {
  let contract: Partial<IngestionConnector> | null = null;
  if (managerContractDefinition) {
    try {
      contract = JSON.parse(managerContractDefinition) as Partial<IngestionConnector>;
    } catch {
      contract = null;
    }
  }
  return {
    deployedVersion: contract?.container_version?.trim() || null,
    slug: managerContractExcerpt?.slug?.trim() || contract?.slug?.trim() || null,
  };
};
