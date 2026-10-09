import React, { BaseSyntheticEvent, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import IconButton from '@common/button/IconButton';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import IngestionCatalogConnectorCreation, { ImportedConnectorConfiguration } from '@components/integrations/catalog/IngestionCatalogConnectorCreation';
import useConnectorDeployDialog from '@components/integrations/catalog/hooks/useConnectorDeployDialog';
import { useConnectorManagerStatus } from '@components/data/connectors/ConnectorManagerStatusContext';
import { ManagedConnectorImportQuery$data } from './__generated__/ManagedConnectorImportQuery.graphql';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const managedConnectorImportQuery = graphql`
  query ManagedConnectorImportQuery($file: Upload!) {
    managedConnectorAddInputFromImport(file: $file) {
      name
      catalog_id
      contract
      confidence_level
      manager_contract_configuration {
        key
        value
      }
      required_at_import
    }
  }
`;

// Imports a managed connector configuration export: opens the deployment drawer
// prefilled with it, the excluded secrets have to be filled in before deploying.
const ManagedConnectorImport = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { hasActiveManagers } = useConnectorManagerStatus();
  const inputFileRef = useRef<HTMLInputElement>(null);
  const [importedConfiguration, setImportedConfiguration] = useState<ImportedConnectorConfiguration | undefined>(undefined);
  const { catalogState, handleOpenDeployDialog, handleCloseDeployDialog, handleCreate } = useConnectorDeployDialog();

  const handleFileImport = async (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const data = await fetchQuery(managedConnectorImportQuery, { file }).toPromise() as ManagedConnectorImportQuery$data;
      const { contract, catalog_id, ...configuration } = data.managedConnectorAddInputFromImport;
      setImportedConfiguration(configuration);
      handleOpenDeployDialog(JSON.parse(contract), catalog_id, hasActiveManagers, 0);
    } catch (e) {
      MESSAGING$.notifyRelayError(e);
    } finally {
      if (inputFileRef.current) {
        inputFileRef.current.value = '';
      }
    }
  };

  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <IconButton
            variant="secondary"
            aria-label={t_i18n('Import a connector')}
            onClick={() => inputFileRef.current?.click()}
          >
            <FileUploadOutlined fontSize="small" />
          </IconButton>
        </TooltipTrigger>
        <TooltipContent>{t_i18n('Import a connector')}</TooltipContent>
      </Tooltip>
      <VisuallyHiddenInput
        ref={inputFileRef}
        type="file"
        accept="application/JSON"
        onChange={handleFileImport}
      />
      {catalogState.selectedConnector && (
        <IngestionCatalogConnectorCreation
          open={!!catalogState.selectedConnector}
          connector={catalogState.selectedConnector}
          onClose={handleCloseDeployDialog}
          catalogId={catalogState.selectedCatalogId}
          isEnterpriseEdition={isEnterpriseEdition}
          hasActiveManagers={catalogState.hasActiveManagers}
          onCreate={handleCreate}
          importedConfiguration={importedConfiguration}
        />
      )}
    </>
  );
};

export default ManagedConnectorImport;
