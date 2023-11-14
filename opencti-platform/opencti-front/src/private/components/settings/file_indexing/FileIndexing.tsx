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
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import FileIndexingRequirements from '@components/settings/file_indexing/FileIndexingRequirements';
import FileIndexingConfigurationAndMonitoring from '@components/settings/file_indexing/FileIndexingConfigurationAndMonitoring';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAuth from '../../../../utils/hooks/useAuth';
import { FILE_INDEX_MANAGER } from '../../../../utils/platformModulesHelper';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FileIndexingConfigurationQuery } from './__generated__/FileIndexingConfigurationQuery.graphql';

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
}

const FileIndexingComponent: FunctionComponent<FileIndexingComponentProps> = ({
  queryRef,
}) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { platformModuleHelpers } = useAuth();
  const isModuleWarning = platformModuleHelpers.isModuleWarning(FILE_INDEX_MANAGER);

  const { managerConfigurationByManagerId } = usePreloadedQuery<FileIndexingConfigurationQuery>(fileIndexingConfigurationQuery, queryRef);

  return (
    <div>
      {!isEnterpriseEdition && (
        <EnterpriseEdition feature={'File indexing'} />
      )}
      <FileIndexingRequirements
        isModuleWarning={isModuleWarning}
      />
      {isEnterpriseEdition && !isModuleWarning && managerConfigurationByManagerId && (
       <FileIndexingConfigurationAndMonitoring managerConfiguration={managerConfigurationByManagerId} />
      )}
    </div>
  );
};

const FileIndexing = () => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingConfigurationQuery>(fileIndexingConfigurationQuery);
  const queryArgs = {
    managerId: FILE_INDEX_MANAGER,
  };
  useEffect(() => {
    loadQuery(queryArgs, { fetchPolicy: 'store-and-network' });
  }, []);
  return (
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <FileIndexingComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.container} />
      )}
    </>
  );
};
export default FileIndexing;
