import React, { FunctionComponent, useState } from 'react';
import StixCoreObjectContentHeader from '@components/common/stix_core_objects/StixCoreObjectContentHeader';
import { Route, Routes, useLocation } from 'react-router-dom';
import ContainerContent, { containerContentQuery } from '@components/common/containers/ContainerContent';
import StixCoreObjectContent from '@components/common/stix_core_objects/StixCoreObjectContent';
import { ContainerContentQuery$data } from '@components/common/containers/__generated__/ContainerContentQuery.graphql';
import { StixCoreObjectContent_stixCoreObject$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContent_stixCoreObject.graphql';
import ContainerSuggestedMappingContent from '@components/common/containers/ContainerSuggestedMappingContent';
import { QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface StixCoreObjectContentRootProps {
  stixCoreObject: StixCoreObjectContent_stixCoreObject$data;
  isContainer?: boolean;
}

const StixCoreObjectContentRoot: FunctionComponent<StixCoreObjectContentRootProps> = ({
  stixCoreObject, isContainer = false,
}) => {
  const [isMappingHeaderDisabled, setMappingHeaderDisabled] = useState<boolean>(false);
  const { pathname } = useLocation();

  const getCurrentMode = (currentPathname: string) => {
    if (currentPathname.endsWith('/mapping')) return 'mapping';
    if (currentPathname.endsWith('/suggested_mapping')) return 'suggested_mapping';
    return 'content';
  };

  const currentMode = getCurrentMode(pathname);
  const modes = isContainer ? ['content', 'suggested_mapping', 'mapping'] : [];
  return (
    <>
      <StixCoreObjectContentHeader
        currentMode={currentMode}
        modes={modes}
        disabled={isMappingHeaderDisabled}
      />
      <Routes>
        <Route
          path="/suggested_mapping"
          element={
            <QueryRenderer
              query={containerContentQuery}
              variables={{ id: stixCoreObject.id }}
              render={({ props } : { props: ContainerContentQuery$data }) => {
                if (props && props.container) {
                  return <ContainerSuggestedMappingContent containerFragment={props.container}/>;
                }
                return (
                  <Loader
                    variant={LoaderVariant.inElement}
                    withTopMargin={true}
                  />
                );
              }}
            />
              }
        />
        <Route
          path="/mapping"
          element={
            <QueryRenderer
              query={containerContentQuery}
              variables={{ id: stixCoreObject.id }}
              render={({ props } : { props: ContainerContentQuery$data }) => {
                if (props && props.container) {
                  return <ContainerContent containerData={props.container}/>;
                }
                return (
                  <Loader
                    variant={LoaderVariant.inElement}
                    withTopMargin={true}
                  />
                );
              }}
            />
          }
        />
        <Route
          path="/"
          element={
            <StixCoreObjectContent
              stixCoreObject={stixCoreObject}
              setMappingHeaderDisabled={setMappingHeaderDisabled}
            />}
        />
      </Routes>
    </>
  );
};

export default StixCoreObjectContentRoot;
