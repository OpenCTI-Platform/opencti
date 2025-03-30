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
import { CancelOutlined, CheckCircleOutlined, CloudUploadOutlined } from '@mui/icons-material';
import ProcessingMenu from '@components/data/ProcessingMenu';
import JsonMappersProvider, { mappersQuery } from '@components/data/jsonMapper/jsonMappers.data';
import { SpeedDialIcon } from '@mui/material';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import SpeedDial from '@mui/material/SpeedDial';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { JsonMapperLine_jsonMapper$data } from '@components/data/jsonMapper/__generated__/JsonMapperLine_jsonMapper.graphql';
import { graphql } from 'react-relay';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
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
  const [_open, _setOpen] = useState(false);
  const [commitImportMutation] = useApiMutation(importMutation);
  // const [importedFileData, setImportedFileData] = useState<JsonMappersImportQuery$data['jsonMapperAddInputFromImport'] | null>(null);

  const inputFileRef = useRef<HTMLInputElement>(null);

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
  // const onClick = () => {
  //   setOpen(true);
  // };

  // const handleClose = () => {
  //   setOpen(false);
  //   // setImportedFileData(null);
  // };

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

  return queryRefMappers
    && (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
        <JsonMappersProvider mappersQueryRef={queryRefMappers}>
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
                    title={t_i18n('Import a JSON mapper')}
                    icon={<CloudUploadOutlined/>}
                    tooltipTitle={t_i18n('Import a JSON mapper')}
                    onClick={() => inputFileRef?.current?.click()}
                    FabProps={{ classes: { root: classes.speedDialButton } }}
                  />
                </SpeedDial>
              </>
            )}
          </div>
        </JsonMappersProvider>
      </Suspense>
    );
};

export default JsonMappers;
