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
import { CsvMappersImportMutation } from '@components/data/__generated__/CsvMappersImportMutation.graphql';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import type { Theme } from '../../../components/Theme';
import { handleError, MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';

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

const csvMapperImportMutation = graphql`
  mutation CsvMappersImportMutation($file: Upload!) {
    csvMapperConfigurationImport(file: $file) {
      id
      entity_type
    }
  }
`;

const CsvMappers = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Processing: CSV Mappers | Data'));
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
  const [commitImportMutation] = useApiMutation<CsvMappersImportMutation>(csvMapperImportMutation);

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

  const handleFileImport = (event: BaseSyntheticEvent) => {
    const importedFile = event.target.files[0];
    if (importedFile) {
      commitImportMutation({
        variables: { file: importedFile },
        onError: (e) => {
          if (inputFileRef.current) inputFileRef.current.value = '';
          handleError(e);
        },
        onCompleted: (response) => {
          if (inputFileRef.current) inputFileRef.current.value = '';
          if (response.csvMapperConfigurationImport) {
            MESSAGING$.notifySuccess(t_i18n('CSV mapper created'));
          }
        },
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
                right: 250,
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
            <CsvMapperCreationContainer
              paginationOptions={paginationOptions}
              open={open}
              onClose={() => setOpen(false)}
            />
          </div>
        </CsvMappersProvider>
      </Suspense>
    );
};

export default CsvMappers;
