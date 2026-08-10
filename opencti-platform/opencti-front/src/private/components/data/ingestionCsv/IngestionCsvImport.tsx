import React, { BaseSyntheticEvent, FunctionComponent, useRef, useState } from 'react';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { IngestionCsvCreationContainer } from '@components/data/ingestionCsv/IngestionCsvCreation';
import { IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { IngestionCsvImportQuery$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvImportQuery.graphql';
import { IngestionCsvEditionFragment_ingestionCsv$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionFragment_ingestionCsv.graphql';
import { FileUploadOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton/ToggleButton';
import { useNavigate, useParams } from 'react-router-dom';
import XtmHubDialogConnectivityLost from '@components/xtm_hub/dialog/connectivity-lost';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useXtmHubDownloadDocument from '../../../../utils/hooks/useXtmHubDownloadDocument';

export const csvFeedImportQuery = graphql`
  query IngestionCsvImportQuery($file: Upload!) {
    csvFeedAddInputFromImport(file: $file) {
      authentication_type
      description
      name
      uri
      markings
      authentication_value
      csv_mapper_type
      scheduling_period
      csvMapper {
        name
        has_header
        separator
        skipLineChar
        representations {
          id
          type
          target {
            entity_type
            column_based {
              column_reference
              operator
              value
            }
          }
          attributes {
            key
            column {
              column_name
              configuration {
                separator
                pattern_date
              }
            }
            default_values {
              id
              name
            }
            based_on {
              representations
            }
          }
        }
      }
    }
  }
`;

interface IngestionCsvImportProps {
  paginationOptions?: IngestionCsvLinesPaginationQuery$variables | null | undefined;
  // Hide the upload toggle when the import is driven externally (Hub deep link).
  hideTrigger?: boolean;
  // Called when the prefilled creation drawer closes (creation or cancel).
  onClose?: () => void;
}
const IngestionCsvImport: FunctionComponent<IngestionCsvImportProps> = ({
  paginationOptions,
  hideTrigger,
  onClose,
}) => {
  const { fileId, serviceInstanceId } = useParams();
  const navigate = useNavigate();
  const inputFileRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState<boolean>(false);
  const [ingestCSVData, setIngestCSVData] = useState<
    IngestionCsvImportQuery$data['csvFeedAddInputFromImport'] | undefined
  >(undefined);
  const { t_i18n } = useFormatter();

  const handleFileImport = (file: File) => {
    if (file) {
      fetchQuery(csvFeedImportQuery, { file })
        .toPromise()
        .then((data) => {
          const { csvFeedAddInputFromImport } = data as IngestionCsvImportQuery$data;
          setIngestCSVData(csvFeedAddInputFromImport);
          setOpen(true);
          if (inputFileRef.current) {
            inputFileRef.current.value = '';
          }
        })
        .catch((e) => {
          MESSAGING$.notifyRelayError(e);
        });
    }
  };

  const fileImport = (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    handleFileImport(file);
  };

  const onDownloadError = () => {
    navigate('/dashboard/integrations/deployed?kind=csv');
    MESSAGING$.notifyError(t_i18n('An error occurred while importing CSV Feed configuration.'));
  };

  const { dialogConnectivityLostStatus } = useXtmHubDownloadDocument({
    serviceInstanceId,
    fileId,
    onSuccess: handleFileImport,
    onError: onDownloadError,
  });

  const onConfirm = () => {
    navigate('/redirect/connect-xtm-hub');
  };

  const onCancel = () => {
    navigate('/dashboard/workspaces/dashboards');
  };

  return (
    <>
      <XtmHubDialogConnectivityLost
        status={dialogConnectivityLostStatus}
        onConfirm={onConfirm}
        onCancel={onCancel}
      />
      {!hideTrigger && (
        <ToggleButton
          value="import"
          size="small"
          sx={{ marginLeft: 1 }}
          title={t_i18n('Import a CSV Feed')}
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
      <IngestionCsvCreationContainer
        ingestionCsvData={
          {
            ...ingestCSVData,
          } as unknown as IngestionCsvEditionFragment_ingestionCsv$data
        }
        triggerButton={false}
        handleClose={() => {
          setOpen(false);
          onClose?.();
        }}
        open={open}
        paginationOptions={paginationOptions}
        drawerSettings={{
          title: t_i18n('Import a CSV Feed'),
          button: t_i18n('Create'),
        }}
      />
    </>
  );
};

export default IngestionCsvImport;
