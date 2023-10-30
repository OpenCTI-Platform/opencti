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
import {
  FileIndexingConfigurationFilesMetricsQuery,
} from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationFilesMetricsQuery.graphql';
import FileIndexingConfigurationRequirements
  from '@components/settings/file_indexing/FileIndexingConfigurationRequirements';
import FileIndexingConfigurationAndImpact from '@components/settings/file_indexing/FileIndexingConfigurationAndImpact';
import FileIndexingConfigurationInformations
  from '@components/settings/file_indexing/FileIndexingConfigurationInformations';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAuth from '../../../../utils/hooks/useAuth';
import { FILE_INDEX_MANAGER } from '../../../../utils/platformModulesHelper';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const fileIndexingConfigurationFilesMetricsQuery = graphql`
  query FileIndexingConfigurationFilesMetricsQuery($mimeTypes: [String]) {
    filesMetrics(mimeTypes: $mimeTypes) {
      globalCount
      globalSize
    }
  }
`;

interface FileIndexingConfigurationComponentProps {
  queryRef: PreloadedQuery<FileIndexingConfigurationFilesMetricsQuery>
}

const FileIndexingConfigurationComponent: FunctionComponent<FileIndexingConfigurationComponentProps> = ({
  queryRef,
}) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { platformModuleHelpers } = useAuth();
  const isModuleWarning = platformModuleHelpers.isModuleWarning(FILE_INDEX_MANAGER);
  const isStarted = false; // TODO get from config

  const { filesMetrics } = usePreloadedQuery<FileIndexingConfigurationFilesMetricsQuery>(fileIndexingConfigurationFilesMetricsQuery, queryRef);

  const totalFiles = filesMetrics?.globalCount;
  const dataToIndex = filesMetrics?.globalSize;
  const indexedFiles = 2;
  const volumeIndexed = 1;

  const handleStart = () => {};
  const handlePause = () => {};

  return (
    <div>
      {!isEnterpriseEdition && (
        <EnterpriseEdition />
      )}
      <FileIndexingConfigurationRequirements
        isModuleWarning={isModuleWarning}
      />
        {isEnterpriseEdition && !isModuleWarning && (
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
               handleStart={handleStart}
               handlePause={handlePause}
             />
            </Grid>
          </Grid>
        )}
    </div>
  );
};

const FileIndexingConfiguration = () => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingConfigurationFilesMetricsQuery>(fileIndexingConfigurationFilesMetricsQuery);
  useEffect(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
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
