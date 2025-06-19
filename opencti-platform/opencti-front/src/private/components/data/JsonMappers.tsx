/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { BaseSyntheticEvent, Suspense, useRef, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import JsonMapperLines from '@components/data/jsonMapper/JsonMapperLines';
import { CancelOutlined, CheckCircleOutlined } from '@mui/icons-material';
import ProcessingMenu from '@components/data/ProcessingMenu';
import JsonMappersProvider, { mappersQuery } from '@components/data/jsonMapper/jsonMappers.data';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { JsonMapperLine_jsonMapper$data } from '@components/data/jsonMapper/__generated__/JsonMapperLine_jsonMapper.graphql';
import { graphql } from 'react-relay';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import JsonMapperCreationContainer from '@components/data/jsonMapper/JsonMapperCreationContainer';
import { schemaAttributesQuery } from '@components/data/csvMapper/csvMappers.data';
import { jsonMappers_SchemaAttributesQuery } from '@components/data/jsonMapper/__generated__/jsonMappers_SchemaAttributesQuery.graphql';
import Button from '@mui/material/Button';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import type { Theme } from '../../../components/Theme';
import { jsonMappers_MappersQuery, jsonMappers_MappersQuery$variables } from './jsonMapper/__generated__/jsonMappers_MappersQuery.graphql';
import { handleError } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';

const LOCAL_STORAGE_KEY_JSON_MAPPERS = 'jsonMappers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  container: {
    paddingRight: '200px',
  },
}));

export const importMutation = graphql`
  mutation JsonMappersImportMutation($file: Upload!) {
    jsonMapperImport(file: $file)
  }
`;

const JsonMappers = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('JSON Mappers | Processing | Data'));
  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<jsonMappers_MappersQuery$variables>(
    LOCAL_STORAGE_KEY_JSON_MAPPERS,
    {
      sortBy: 'name',
      orderAsc: false,
      view: 'lines',
      searchTerm: '',
    },
  );
  const [open, setOpen] = useState(false);
  const handleClose = () => {
    setOpen(false);
  };

  const [commitImportMutation] = useApiMutation(importMutation);

  const inputFileRef = useRef<HTMLInputElement>(null);

  const queryRefSchemaAttributes = useQueryLoading<jsonMappers_SchemaAttributesQuery>(
    schemaAttributesQuery,
  );
  const queryRefMappers = useQueryLoading<jsonMappers_MappersQuery>(
    mappersQuery,
    paginationOptions,
  );

  const dataColumns = {
    name: {
      label: 'Name',
      width: '80%',
      isSortable: true,
      render: (data: JsonMapperLine_jsonMapper$data) => data.name,
    },
    validity: {
      label: 'Validity',
      width: '20%',
      isSortable: false,
      render: (data: JsonMapperLine_jsonMapper$data) => {
        return data.errors === null ? (
          <CheckCircleOutlined fontSize="small" color="success"/>
        ) : (
          <CancelOutlined fontSize="small" color="error"/>
        );
      },
    },
  };

  const handleFileImport = (event: BaseSyntheticEvent) => {
    const importedFile = event.target.files[0];
    commitImportMutation({
      variables: { file: importedFile },
      onCompleted: (_data) => {
        if (inputFileRef.current) {
          inputFileRef.current.value = ''; // Reset the input uploader ref
        }
        window.location.reload();
      },
      onError: (error) => {
        if (inputFileRef.current) {
          inputFileRef.current.value = ''; // Reset the input uploader ref
        }
        handleError(error);
      },
    });
  };

  return queryRefMappers && queryRefSchemaAttributes
    && (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
        <JsonMappersProvider mappersQueryRef={queryRefMappers} schemaAttributesQueryRef={queryRefSchemaAttributes}>
          <div className={classes.container}>
            <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Processing') }, { label: t_i18n('JSON mappers'), current: true }]} />
            <ProcessingMenu />
            {!isEnterpriseEdition ? (
              <EnterpriseEdition feature="Dissemination lists" />
            ) : (
              <>
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
                  createButton={(
                    <>
                      <>
                        <Button
                          variant='outlined'
                          disableElevation
                          sx={{ marginLeft: 1 }}
                          onClick={() => inputFileRef?.current?.click()}
                        >
                          {t_i18n('Import a JSON mapper')}
                        </Button>
                        <Button
                          variant='contained'
                          disableElevation
                          sx={{ marginLeft: 1 }}
                          onClick={() => setOpen(true)}
                        >
                          {t_i18n('Create a JSON mapper')}
                        </Button>
                      </>
                    </>
                  )}
                >
                  <React.Suspense
                    fallback={<Loader variant={LoaderVariant.inElement}/>}
                  >
                    <JsonMapperLines
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
                <JsonMapperCreationContainer
                  paginationOptions={paginationOptions}
                  open={open}
                  onClose={handleClose}
                />
              </>
            )}
          </div>
        </JsonMappersProvider>
      </Suspense>
    );
};

export default JsonMappers;
