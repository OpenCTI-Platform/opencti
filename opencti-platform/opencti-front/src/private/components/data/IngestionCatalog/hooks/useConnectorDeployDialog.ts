import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import { resolveLink } from '../../../../../utils/Entity';

interface CatalogState {
  selectedConnector: IngestionConnector | null;
  selectedCatalogId: string;
  hasRegisteredManagers: boolean;
  hasActiveManagers: boolean;
  deploymentCount: number
}

const useConnectorDeployDialog = () => {
  const navigate = useNavigate();

  const [catalogState, setCatalogState] = useState<CatalogState>({
    selectedConnector: null,
    selectedCatalogId: '',
    hasRegisteredManagers: false,
    hasActiveManagers: false,
    deploymentCount: 0,
  });

  const handleOpenDeployDialog = (
    connector: IngestionConnector,
    catalogId: string,
    registeredManagers: boolean,
    activeManagers: boolean,
    deploymentCount: number,
  ) => {
    setCatalogState((prev) => ({
      ...prev,
      selectedConnector: connector,
      selectedCatalogId: catalogId,
      hasRegisteredManagers: registeredManagers,
      hasActiveManagers: activeManagers,
      deploymentCount,
    }));
  };

  const handleCloseDeployDialog = () => {
    setCatalogState((prev) => ({
      ...prev,
      selectedConnector: null,
      selectedCatalogId: '',
    }));
  };

  const handleCreate = (connectorId: string) => {
    navigate(`${resolveLink('Connectors')}/${connectorId}`);
  };

  return {
    catalogState,
    handleOpenDeployDialog,
    handleCloseDeployDialog,
    handleCreate,
  };
};

export default useConnectorDeployDialog;
