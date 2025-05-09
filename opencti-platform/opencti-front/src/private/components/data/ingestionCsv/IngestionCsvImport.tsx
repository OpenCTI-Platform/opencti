import Button from '@mui/material/Button';
import React, { BaseSyntheticEvent, FunctionComponent, useRef, useState } from 'react';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { IngestionCsvCreationContainer } from '@components/data/ingestionCsv/IngestionCsvCreation';
import { IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { IngestionCsvImportQuery$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvImportQuery.graphql';
import { IngestionCsvEditionFragment_ingestionCsv$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionFragment_ingestionCsv.graphql';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { RelayError } from '../../../../relay/relayTypes';

export const csvFeedImportQuery = graphql`
  query IngestionCsvImportQuery($file: Upload!) {
    csvFeedAddInputFromImport(file: $file) {
      authentication_type
      description
      name
      uri
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
}
const IngestionCsvImport: FunctionComponent<IngestionCsvImportProps> = ({ paginationOptions }) => {
  const inputFileRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState<boolean>(false);
  const [ingestCSVData, setIngestCSVData] = useState<IngestionCsvImportQuery$data['csvFeedAddInputFromImport'] | undefined>(undefined);
  const { t_i18n } = useFormatter();
  const handleFileImport = (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    if (file) {
      fetchQuery(csvFeedImportQuery, { file })
        .toPromise()
        .then((data) => {
          const { csvFeedAddInputFromImport } = data as IngestionCsvImportQuery$data;
          setIngestCSVData(csvFeedAddInputFromImport);
          setOpen(true);
        })
        .catch((e) => {
          const { errors } = (e as unknown as RelayError).res;
          MESSAGING$.notifyError(errors.at(0)?.message);
        });
    }
  };
  return <>
    <Button
      variant='outlined'
      disableElevation
      sx={{ marginLeft: 1 }}
      onClick={() => inputFileRef?.current?.click()}
    >
      {t_i18n('Import a CSV feed')}
    </Button>
    <VisuallyHiddenInput
      ref={inputFileRef}
      type="file"
      accept={'application/JSON'}
      onChange={handleFileImport}
    />
    <IngestionCsvCreationContainer
      ingestionCsvData={{
        ...ingestCSVData,
        markings: [],
        authentication_value: '',
        // TODO rewrite this model or modify form
      } as unknown as IngestionCsvEditionFragment_ingestionCsv$data }
      handleClose={() => setOpen(false)}
      open={open}
      paginationOptions={paginationOptions}
      drawerSettings={{
        title: t_i18n('Import a CSV feed'),
        button: t_i18n('Create'),
      }}
    /></>;
};

export default IngestionCsvImport;
