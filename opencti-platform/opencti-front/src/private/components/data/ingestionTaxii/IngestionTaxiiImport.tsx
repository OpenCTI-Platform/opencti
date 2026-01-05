import React, { BaseSyntheticEvent, FunctionComponent, useRef, useState } from 'react';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton/ToggleButton';
import { useNavigate, useParams } from 'react-router-dom';
import XtmHubDialogConnectivityLost from '@components/xtm_hub/dialog/connectivity-lost';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { RelayError } from '../../../../relay/relayTypes';
import useXtmHubDownloadDocument from '../../../../utils/hooks/useXtmHubDownloadDocument';
import { PaginationOptions } from '../../../../components/list_lines';
import { IngestionTaxiiImportQuery$data } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiImportQuery.graphql';
import IngestionTaxiiCreation from '@components/data/ingestionTaxii/IngestionTaxiiCreation';

export const taxiiFeedImportQuery = graphql`
  query IngestionTaxiiImportQuery($file: Upload!) {
    taxiiFeedAddInputFromImport(file: $file) {
        name
        description
        uri
        version
        collection
        authentication_type
        added_after_start
    }
  }
`;

interface IngestionTaxiiImportProps {
  paginationOptions: PaginationOptions;
}
const IngestionTaxiiImport: FunctionComponent<IngestionTaxiiImportProps> = ({ paginationOptions }) => {
  const { fileId, serviceInstanceId } = useParams();
  const navigate = useNavigate();
  const inputFileRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState<boolean>(false);
  const [ingestTaxiiData, setIngestTaxiiData] = useState<IngestionTaxiiImportQuery$data['taxiiFeedAddInputFromImport'] | undefined>(undefined);
  const { t_i18n } = useFormatter();

  const handleFileImport = async (file: File) => {
    if (!file) return;
    try {
      const data = await fetchQuery(taxiiFeedImportQuery, { file }).toPromise();
      const { taxiiFeedAddInputFromImport } = data as IngestionTaxiiImportQuery$data;
      setIngestTaxiiData(taxiiFeedAddInputFromImport);
      setOpen(true);
      if (inputFileRef.current) {
        inputFileRef.current.value = '';
      }
    } catch (e) {
      const { errors } = (e as unknown as RelayError).res;
      MESSAGING$.notifyError(errors.at(0)?.message);
    }
  };

  const fileImport = (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    handleFileImport(file);
  };

  const handleDownloadError = () => {
    navigate('/dashboard/data/ingestion/taxii');
    MESSAGING$.notifyError(t_i18n('An error occurred while importing Taxii Feed configuration.'));
  };

  const { dialogConnectivityLostStatus } = useXtmHubDownloadDocument({
    serviceInstanceId,
    fileId,
    onSuccess: handleFileImport,
    onError: handleDownloadError,
  });

  const handleConfirm = () => {
    navigate('/dashboard/settings/experience');
  };

  const handleCancel = () => {
    navigate('/dashboard/workspaces/dashboards');
  };

  return (
    <>
      <XtmHubDialogConnectivityLost
        status={dialogConnectivityLostStatus}
        onConfirm={handleConfirm}
        onCancel={handleCancel}
      />
      <ToggleButton
        value="import"
        size="small"
        sx={{ marginLeft: 1 }}
        title={t_i18n('Import a Taxii Feed')}
        onClick={() => inputFileRef?.current?.click()}
      >
        <FileUploadOutlined fontSize="small" color="primary" />
      </ToggleButton>
      <VisuallyHiddenInput
        ref={inputFileRef}
        type="file"
        accept="application/JSON"
        onChange={fileImport}
      />
      <IngestionTaxiiCreation
        open={open}
        handleClose={() => setOpen(false)}
        ingestionTaxiiData={ingestTaxiiData}
        paginationOptions={paginationOptions}
        triggerButton={false}
        drawerSettings={{
          title: t_i18n('Import a Taxii Feed'),
          button: t_i18n('Create'),
        }}
      />
    </>
  );
};

export default IngestionTaxiiImport;
