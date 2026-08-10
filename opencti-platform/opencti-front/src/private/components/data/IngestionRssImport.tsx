import React, { BaseSyntheticEvent, FunctionComponent, useRef, useState } from 'react';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton/ToggleButton';
import { useNavigate, useParams } from 'react-router-dom';
import XtmHubDialogConnectivityLost from '@components/xtm_hub/dialog/connectivity-lost';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import useXtmHubDownloadDocument from '../../../utils/hooks/useXtmHubDownloadDocument';
import IngestionRssCreation from '@components/data/ingestionRss/IngestionRssCreation';
import { IngestionRssImportQuery$data } from '@components/data/__generated__/IngestionRssImportQuery.graphql';
import { useFormatter } from '../../../components/i18n';
import { IngestionRssLinesDataTableQuery$variables } from '@components/data/ingestionRss/__generated__/IngestionRssLinesDataTableQuery.graphql';

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
  paginationOptions: IngestionRssLinesDataTableQuery$variables;
  // Hide the upload toggle when the import is driven externally (Hub deep link).
  hideTrigger?: boolean;
  // Called when the prefilled creation drawer closes (creation or cancel).
  onClose?: () => void;
}
const IngestionRssImport: FunctionComponent<IngestionRssImportProps> = ({
  paginationOptions,
  hideTrigger,
  onClose,
}) => {
  const { fileId, serviceInstanceId } = useParams();
  const navigate = useNavigate();
  const inputFileRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState<boolean>(false);
  const [ingestRssData, setIngestRssData] = useState<
    IngestionRssImportQuery$data['ingestionRssAddInputFromImport'] | undefined
  >(undefined);
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
      MESSAGING$.notifyRelayError(e);
    }
  };

  const fileImport = (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    handleFileImport(file);
  };

  const handleDownloadError = () => {
    navigate('/dashboard/integrations/deployed?kind=rss');
    MESSAGING$.notifyError(t_i18n('An error occurred while importing RSS Feed configuration.'));
  };

  const { dialogConnectivityLostStatus } = useXtmHubDownloadDocument({
    serviceInstanceId,
    fileId,
    onSuccess: handleFileImport,
    onError: handleDownloadError,
  });

  const handleConfirm = () => {
    navigate('/redirect/connect-xtm-hub');
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
      {!hideTrigger && (
        <ToggleButton
          value="import"
          size="small"
          sx={{ marginLeft: 1 }}
          title={t_i18n('Import an RSS Feed')}
          onClick={() => inputFileRef?.current?.click()}
        >
          <FileUploadOutlined fontSize="small" color="primary" />
        </ToggleButton>
      )}
      <VisuallyHiddenInput
        ref={inputFileRef}
        type="file"
        accept="application/JSON"
        onChange={fileImport}
      />
      <IngestionRssCreation
        open={open}
        handleClose={() => {
          setOpen(false);
          onClose?.();
        }}
        ingestionRssData={ingestRssData}
        paginationOptions={paginationOptions}
        triggerButton={false}
        drawerSettings={{
          title: t_i18n('Import an RSS Feed'),
          button: t_i18n('Create'),
        }}
      />
    </>
  );
};

export default IngestionRssImport;
