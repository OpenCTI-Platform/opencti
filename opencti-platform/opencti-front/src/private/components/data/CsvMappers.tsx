import React, { BaseSyntheticEvent, Suspense, useRef, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import CsvMapperLines from '@components/data/csvMapper/CsvMapperLines';
import CsvMapperCreationContainer from '@components/data/csvMapper/CsvMapperCreationContainer';
import { CsvMapperLine_csvMapper$data } from '@components/data/csvMapper/__generated__/CsvMapperLine_csvMapper.graphql';
import { CancelOutlined, CheckCircleOutlined, CloudUploadOutlined, WidgetsOutlined } from '@mui/icons-material';
import ProcessingMenu from '@components/data/ProcessingMenu';
import CsvMappersProvider, { mappersQuery, schemaAttributesQuery } from '@components/data/csvMapper/csvMappers.data';
import { csvMappers_MappersQuery, csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { csvMappers_SchemaAttributesQuery } from '@components/data/csvMapper/__generated__/csvMappers_SchemaAttributesQuery.graphql';
import { SpeedDialIcon } from '@mui/material';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import SpeedDial from '@mui/material/SpeedDial';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { CsvMappersImportQuery$data } from '@components/data/__generated__/CsvMappersImportQuery.graphql';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import type { Theme } from '../../../components/Theme';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';

const LOCAL_STORAGE_KEY_CSV_MAPPERS = 'csvMappers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    paddingRight: '200px',
  },
  speedDialButton: {
    backgroundColor: theme.palette.primary.main,
    color: theme.palette.primary.contrastText,
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
  },
}));

export const csvMappersImportQuery = graphql`
  query CsvMappersImportQuery($file: Upload!) {
    csvMapperAddInputFromImport(file: $file) {
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
`;

const CsvMappers = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('CSV Mappers | Processing | Data'));
  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<csvMappers_MappersQuery$variables>(
    LOCAL_STORAGE_KEY_CSV_MAPPERS,
    {
      sortBy: 'name',
      orderAsc: false,
      view: 'lines',
      searchTerm: '',
    },
  );
  const [open, setOpen] = useState(false);

  const [importedFileData, setImportedFileData] = useState<CsvMappersImportQuery$data['csvMapperAddInputFromImport'] | null>(null);

  const inputFileRef = useRef<HTMLInputElement>(null);

  const queryRefSchemaAttributes = useQueryLoading<csvMappers_SchemaAttributesQuery>(
    schemaAttributesQuery,
  );
  const queryRefMappers = useQueryLoading<csvMappers_MappersQuery>(
    mappersQuery,
    paginationOptions,
  );

  const dataColumns = {
    name: {
      label: 'Name',
      width: '80%',
      isSortable: true,
      render: (data: CsvMapperLine_csvMapper$data) => data.name,
    },
    validity: {
      label: 'Validity',
      width: '20%',
      isSortable: false,
      render: (data: CsvMapperLine_csvMapper$data) => {
        return data.errors === null ? (
          <CheckCircleOutlined fontSize="small" color="success"/>
        ) : (
          <CancelOutlined fontSize="small" color="error"/>
        );
      },
    },
  };
  const onClick = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setImportedFileData(null);
  };

  const handleFileImport = (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    if (file) {
      fetchQuery(csvMappersImportQuery, { file })
        .toPromise()
        .then((data) => {
          const { csvMapperAddInputFromImport } = data as CsvMappersImportQuery$data;
          setImportedFileData(csvMapperAddInputFromImport);
        })
        .catch((e) => {
          const { errors } = (e as unknown as RelayError).res;
          MESSAGING$.notifyError(errors.at(0)?.message);
        });
    }
  };

  return queryRefMappers && queryRefSchemaAttributes
    && (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
        <CsvMappersProvider
          mappersQueryRef={queryRefMappers}
          schemaAttributesQueryRef={queryRefSchemaAttributes}
        >
          <div className={classes.container}>
            <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Processing') }, { label: t_i18n('CSV mappers'), current: true }]} />
            <ProcessingMenu />
            <ListLines
              helpers={helpers}
              sortBy={viewStorage.sortBy}
              orderAsc={viewStorage.orderAsc}
              dataColumns={dataColumns}
              handleSort={helpers.handleSort}
              handleSearch={helpers.handleSearch}
              displayImport={false}
              secondaryAction={true}
              keyword={viewStorage.searchTerm}
              paginationOptions={paginationOptions}
              numberOfElements={viewStorage.numberOfElements}
            >
              <React.Suspense
                fallback={<Loader variant={LoaderVariant.inElement}/>}
              >
                <CsvMapperLines
                  paginationOptions={paginationOptions}
                  dataColumns={dataColumns}
                />
              </React.Suspense>
            </ListLines>
            <VisuallyHiddenInput
              ref={inputFileRef}
              type="file"
              accept={'application/JSON'}
              onChange={handleFileImport}
            />
            <SpeedDial
              style={{
                position: 'fixed',
                bottom: 30,
                right: 230,
                zIndex: 1100,
              }}
              ariaLabel="Create"
              icon={<SpeedDialIcon/>}
              FabProps={{ color: 'primary' }}
            >
              <SpeedDialAction
                title={t_i18n('Create a CSV mapper')}
                icon={<WidgetsOutlined/>}
                tooltipTitle={t_i18n('Create a CSV mapper')}
                onClick={onClick}
                FabProps={{ classes: { root: classes.speedDialButton } }}
              />
              <SpeedDialAction
                title={t_i18n('Import a CSV mapper')}
                icon={<CloudUploadOutlined/>}
                tooltipTitle={t_i18n('Import a CSV mapper')}
                onClick={() => inputFileRef?.current?.click()}
                FabProps={{ classes: { root: classes.speedDialButton } }}
              />
            </SpeedDial>
            {importedFileData
              ? <CsvMapperCreationContainer
                  importedFileData={importedFileData}
                  paginationOptions={paginationOptions}
                  open={true}
                  onClose={handleClose}
                />
              : <CsvMapperCreationContainer
                  paginationOptions={paginationOptions}
                  open={open}
                  onClose={handleClose}
                />
            }
          </div>
        </CsvMappersProvider>
      </Suspense>
    );
};

export default CsvMappers;
