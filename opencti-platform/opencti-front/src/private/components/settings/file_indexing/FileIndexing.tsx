/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { FunctionComponent, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import FileIndexingConfigurationAndMonitoring from '@components/settings/file_indexing/FileIndexingConfigurationAndMonitoring';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import { interval } from 'rxjs';
import Alert from '@mui/material/Alert';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAuth from '../../../../utils/hooks/useAuth';
import { FILE_INDEX_MANAGER } from '../../../../utils/platformModulesHelper';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FileIndexingConfigurationQuery } from './__generated__/FileIndexingConfigurationQuery.graphql';
import { TEN_SECONDS } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';

const interval$ = interval(TEN_SECONDS);

const fileIndexingConfigurationQuery = graphql`
  query FileIndexingConfigurationQuery($managerId: String!) {
    managerConfigurationByManagerId(managerId: $managerId) {
      id
      manager_id
      manager_running
      last_run_start_date
      last_run_end_date
      manager_setting
    }
  }
`;

export const fileIndexingConfigurationFieldPatch = graphql`
  mutation FileIndexingConfigurationFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    managerConfigurationFieldPatch(id: $id, input: $input) {
      id
      manager_id
      manager_running
      manager_setting
    }
  }
`;

export const fileIndexingResetMutation = graphql`
  mutation FileIndexingResetMutation {
    resetFileIndexing
  }
`;

interface FileIndexingComponentProps {
  queryRef: PreloadedQuery<FileIndexingConfigurationQuery>;
  refetch: () => void;
}

const FileIndexingComponent: FunctionComponent<FileIndexingComponentProps> = ({
  queryRef,
  refetch,
}) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { platformModuleHelpers } = useAuth();
  const isModuleWarning = platformModuleHelpers.isModuleWarning(FILE_INDEX_MANAGER);
  const { managerConfigurationByManagerId } = usePreloadedQuery<FileIndexingConfigurationQuery>(
    fileIndexingConfigurationQuery,
    queryRef,
  );
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);
  return (
    <>
      {!isEnterpriseEdition ? (
        <EnterpriseEdition feature="File indexing" />
      ) : (
        <>
          {isModuleWarning ? (
            <Alert
              severity="warning"
              variant="outlined"
              style={{ position: 'relative' }}
            >
              {t_i18n(
                'It seems that your OpenCTI stack is not supporting file indexing. Please ensure you meet',
              )}{' '}
              <strong>{t_i18n('one of the following requirements:')}</strong>
              <ul>
                <li>Elasticsearch &ge; 8.4</li>
                <li>
                  Elasticsearch &lt; 8.4 with{' '}
                  <span style={{ fontFamily: 'Consolas, monaco, monospace' }}>
                    ingest-attachment
                  </span>{' '}
                  plugin enabled
                </li>
                <li>
                  OpenSearch with{' '}
                  <span style={{ fontFamily: 'Consolas, monaco, monospace' }}>
                    ingest-attachment
                  </span>{' '}
                  plugin
                </li>
              </ul>
            </Alert>
          ) : (
            <FileIndexingConfigurationAndMonitoring
              managerConfiguration={managerConfigurationByManagerId}
            />
          )}
        </>
      )}
    </>
  );
};

const FileIndexing = () => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingConfigurationQuery>(
    fileIndexingConfigurationQuery,
  );
  const queryArgs = {
    managerId: FILE_INDEX_MANAGER,
  };
  useEffect(() => {
    loadQuery(queryArgs, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetch = React.useCallback(() => {
    loadQuery(queryArgs, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);

  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <FileIndexingComponent queryRef={queryRef} refetch={refetch} />
        </React.Suspense>
      )}
    </>
  );
};
export default FileIndexing;
