import React, { FunctionComponent, useState } from 'react';
import StixCoreObjectContentHeader from '@components/common/stix_core_objects/StixCoreObjectContentHeader';
import { Route, Routes, useLocation } from 'react-router-dom';
import StixCoreObjectContent from '@components/common/stix_core_objects/StixCoreObjectContent';
import { StixCoreObjectContent_stixCoreObject$key } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContent_stixCoreObject.graphql';
import ContainerMappingContent, { containerContentQuery } from '@components/common/containers/ContainerMappingContent';
import { ContainerMappingContentQuery$data } from '@components/common/containers/__generated__/ContainerMappingContentQuery.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface StixCoreObjectContentRootProps {
  stixCoreObject: { id: string } & StixCoreObjectContent_stixCoreObject$key;
  isContainer?: boolean;
}

const StixCoreObjectContentRoot: FunctionComponent<StixCoreObjectContentRootProps> = ({
  stixCoreObject, isContainer = false,
}) => {
  const [isMappingHeaderDisabled, setMappingHeaderDisabled] = useState<boolean>(false);
  const { pathname } = useLocation();

  const getCurrentMode = (currentPathname: string) => {
    if (currentPathname.endsWith('/mapping')) return 'mapping';
    return 'content';
  };

  const currentMode = getCurrentMode(pathname);
  const modes = isContainer ? ['content', 'mapping'] : [];
  return (
    <>
      <StixCoreObjectContentHeader
        currentMode={currentMode}
        modes={modes}
        disabled={isMappingHeaderDisabled}
      />
      <Routes>
        <Route
          path="/mapping"
          element={
            <QueryRenderer
              query={containerContentQuery}
              variables={{ id: stixCoreObject.id }}
              render={({ props } : { props: ContainerMappingContentQuery$data }) => {
                if (props && props.container) {
                  return <ContainerMappingContent containerFragment={props.container}/>;
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
