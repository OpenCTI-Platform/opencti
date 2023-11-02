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
import FileIndexingConfigurationRequirements
  from '@components/settings/file_indexing/FileIndexingConfigurationRequirements';
import FileIndexingConfigurationAndImpact from '@components/settings/file_indexing/FileIndexingConfigurationAndImpact';
import FileIndexingConfigurationInformations
  from '@components/settings/file_indexing/FileIndexingConfigurationInformations';
import {
  FileIndexingConfigurationQuery,
} from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationQuery.graphql';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAuth from '../../../../utils/hooks/useAuth';
import { FILE_INDEX_MANAGER } from '../../../../utils/platformModulesHelper';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const fileIndexingConfigurationQuery = graphql`
  query FileIndexingConfigurationQuery($managerId: String!, $mimeTypes: [String]) {
    managerConfigurationByManagerId(managerId: $managerId) {
      id
      manager_id
      manager_running
      last_run_start_date
      last_run_end_date
    }
    filesMetrics(mimeTypes: $mimeTypes) {
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

interface FileIndexingConfigurationComponentProps {
  queryRef: PreloadedQuery<FileIndexingConfigurationQuery>
}

const FileIndexingConfigurationComponent: FunctionComponent<FileIndexingConfigurationComponentProps> = ({
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
  const indexedFiles = 2;
  const volumeIndexed = 1;

  return (
    <div>
      {!isEnterpriseEdition && (
        <EnterpriseEdition />
      )}
      <FileIndexingConfigurationRequirements
        isModuleWarning={isModuleWarning}
      />
        {isEnterpriseEdition && !isModuleWarning && managerConfigurationByManagerId && (
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
             <FileIndexingConfigurationAndImpact
               totalFiles={totalFiles}
               dataToIndex={dataToIndex}
             />
            </Grid>
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
             <FileIndexingConfigurationInformations
               indexedFiles={indexedFiles}
               totalFiles={totalFiles}
               volumeIndexed={volumeIndexed}
               isStarted={isStarted}
               managerConfigurationId={managerConfigurationId}
             />
            </Grid>
          </Grid>
        )}
    </div>
  );
};

const FileIndexingConfiguration = () => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingConfigurationQuery>(fileIndexingConfigurationQuery);
  useEffect(() => {
    loadQuery({ managerId: FILE_INDEX_MANAGER }, { fetchPolicy: 'store-and-network' });
  }, []);
  return (
      <>
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
            <FileIndexingConfigurationComponent
              queryRef={queryRef}
            />
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.container} />
        )}
      </>
  );
};
export default FileIndexingConfiguration;
