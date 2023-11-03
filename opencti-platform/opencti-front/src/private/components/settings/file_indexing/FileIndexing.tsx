/*
Copyright (c) 2021-2023 Filigran SAS

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
import EnterpriseEdition from '@components/common/EnterpriseEdition';
import Grid from '@mui/material/Grid';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import FileIndexingRequirements
  from '@components/settings/file_indexing/FileIndexingRequirements';
import FileIndexingConfiguration from '@components/settings/file_indexing/FileIndexingConfiguration';
import FileIndexingMonitoring
  from '@components/settings/file_indexing/FileIndexingMonitoring';
import {
  FileIndexingConfigurationQuery,
} from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationQuery.graphql';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAuth from '../../../../utils/hooks/useAuth';
import { FILE_INDEX_MANAGER } from '../../../../utils/platformModulesHelper';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const fileIndexingConfigurationQuery = graphql`
  query FileIndexingConfigurationQuery($managerId: String!, $mimeTypes: [String], $maxFileSize: Float) {
    managerConfigurationByManagerId(managerId: $managerId) {
      id
      manager_id
      manager_running
      last_run_start_date
      last_run_end_date
    }
    filesMetrics(mimeTypes: $mimeTypes, maxFileSize: $maxFileSize) {
      globalCount
      globalSize
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
    }
  }
`;

interface FileIndexingComponentProps {
  queryRef: PreloadedQuery<FileIndexingConfigurationQuery>
}

const FileIndexingComponent: FunctionComponent<FileIndexingComponentProps> = ({
  queryRef,
}) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { platformModuleHelpers } = useAuth();
  const isModuleWarning = platformModuleHelpers.isModuleWarning(FILE_INDEX_MANAGER);

  const { filesMetrics, managerConfigurationByManagerId } = usePreloadedQuery<FileIndexingConfigurationQuery>(fileIndexingConfigurationQuery, queryRef);
  const isStarted = managerConfigurationByManagerId?.manager_running || false;
  const managerConfigurationId = managerConfigurationByManagerId?.id;
  const totalFiles = filesMetrics?.globalCount;
  const dataToIndex = filesMetrics?.globalSize;

  return (
    <div>
      {!isEnterpriseEdition && (
        <EnterpriseEdition />
      )}
      <FileIndexingRequirements
        isModuleWarning={isModuleWarning}
      />
        {isEnterpriseEdition && !isModuleWarning && managerConfigurationByManagerId && (
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
             <FileIndexingConfiguration
               totalFiles={totalFiles}
               dataToIndex={dataToIndex}
             />
            </Grid>
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
             <FileIndexingMonitoring
               totalFiles={totalFiles}
               isStarted={isStarted}
               managerConfigurationId={managerConfigurationId}
             />
            </Grid>
          </Grid>
        )}
    </div>
  );
};

const FileIndexing = () => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingConfigurationQuery>(fileIndexingConfigurationQuery);
  const defaultMimeTypes = ['application/pdf', 'text/plain', 'text/csv', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
  const defaultMaxFileSize = 5242880;
  useEffect(() => {
    loadQuery({ managerId: FILE_INDEX_MANAGER, mimeTypes: defaultMimeTypes, maxFileSize: defaultMaxFileSize }, { fetchPolicy: 'store-and-network' });
  }, []);
  return (
      <>
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
            <FileIndexingComponent
              queryRef={queryRef}
            />
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.container} />
        )}
      </>
  );
};
export default FileIndexing;
