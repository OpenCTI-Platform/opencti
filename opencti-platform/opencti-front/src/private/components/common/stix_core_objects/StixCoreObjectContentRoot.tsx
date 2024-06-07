import React, { FunctionComponent } from 'react';
import StixCoreObjectContentHeader from '@components/common/stix_core_objects/StixCoreObjectContentHeader';
import { Route, Routes, useLocation } from 'react-router-dom';
import ContainerContent, { containerContentQuery } from '@components/common/containers/ContainerContent';
import StixCoreObjectContent from '@components/common/stix_core_objects/StixCoreObjectContent';
import { ContainerContentQuery$data } from '@components/common/containers/__generated__/ContainerContentQuery.graphql';
import { StixCoreObjectContent_stixCoreObject$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContent_stixCoreObject.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useHelper from '../../../../utils/hooks/useHelper';

interface StixCoreObjectContentRootProps {
  stixCoreObject: StixCoreObjectContent_stixCoreObject$data;
  isContainer?: boolean;
}

const StixCoreObjectContentRoot: FunctionComponent<StixCoreObjectContentRootProps> = ({
  stixCoreObject, isContainer = false,
}) => {
  const { pathname } = useLocation();
  const currentMode = pathname.endsWith('/mapping') ? 'mapping' : 'content';
  const modes = isContainer ? ['content', 'mapping'] : [];
  const { isFeatureEnable } = useHelper();
  const contentMappingFeatureFlag = isFeatureEnable('CONTENT_MAPPING');
  return (
    <>
      {contentMappingFeatureFlag && (
        <StixCoreObjectContentHeader
          currentMode={currentMode}
          modes={modes}
        />)
      }
      <Routes>
        <Route
          path="/mapping"
          element={
            <QueryRenderer
              query={containerContentQuery}
              variables={{ id: stixCoreObject.id }}
              render={({ props } : { props: ContainerContentQuery$data }) => {
                if (props && props.container) {
                  return <ContainerContent containerData={props.container} />;
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
            />}
        />
      </Routes>
    </>
  );
};

export default StixCoreObjectContentRoot;
