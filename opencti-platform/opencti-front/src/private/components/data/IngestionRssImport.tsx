import React, { BaseSyntheticEvent, FunctionComponent, useRef, useState } from 'react';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton/ToggleButton';
import { useNavigate, useParams } from 'react-router';
import XtmHubDialogConnectivityLost from '@components/xtm_hub/dialog/connectivity-lost';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';
import useXtmHubDownloadDocument from '../../../utils/hooks/useXtmHubDownloadDocument';
import IngestionRssCreation from '@components/data/ingestionRss/IngestionRssCreation';
import { IngestionRssImportQuery$data } from '@components/data/__generated__/IngestionRssImportQuery.graphql';
import { useFormatter } from '../../../components/i18n';
import { PaginationOptions } from '../../../components/list_lines';

export const rssFeedImportQuery = graphql`
  query IngestionRssImportQuery($file: Upload!) {
    ingestionRssAddInputFromImport(file: $file) {
        name
      description
      scheduling_period
      uri
      current_state_date
      report_types
      object_marking_refs {
        label
        value
      }
    }
  }
`;

interface IngestionRssImportProps {
  paginationOptions: PaginationOptions;
}
const IngestionRssImport: FunctionComponent<IngestionRssImportProps> = ({ paginationOptions }) => {
  const { fileId, serviceInstanceId } = useParams();
  const navigate = useNavigate();
  const inputFileRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState<boolean>(false);
  const [ingestRssData, setIngestRssData] = useState<IngestionRssImportQuery$data['ingestionRssAddInputFromImport'] | undefined>(undefined);
  const { t_i18n } = useFormatter();

  const handleFileImport = async (file: File) => {
    if (!file) return;
    try {
      const data = await fetchQuery(rssFeedImportQuery, { file }).toPromise();
      const { ingestionRssAddInputFromImport } = data as IngestionRssImportQuery$data;
      setIngestRssData(ingestionRssAddInputFromImport);
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
    navigate('/dashboard/data/ingestion/rss');
    MESSAGING$.notifyError(t_i18n('An error occurred while importing RSS Feed configuration.'));
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
        title={t_i18n('Import a RSS Feed')}
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
      <IngestionRssCreation
        open={open}
        handleClose={() => setOpen(false)}
        ingestionRssData={ingestRssData}
        paginationOptions={paginationOptions}
        triggerButton={false}
        drawerSettings={{
          title: t_i18n('Import a RSS Feed'),
          button: t_i18n('Create'),
        }}
      />
    </>
  );
};

export default IngestionRssImport;
