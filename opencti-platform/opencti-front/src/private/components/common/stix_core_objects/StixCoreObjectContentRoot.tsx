import React, { FunctionComponent } from 'react';
import StixCoreObjectContentHeader from '@components/common/stix_core_objects/StixCoreObjectContentHeader';
import { Route, Routes, useLocation } from 'react-router-dom';

import ContainerContent from '@components/common/containers/ContainerContent';
import StixCoreObjectContent from '@components/common/stix_core_objects/StixCoreObjectContent';

interface StixCoreObjectContentRootProps {
  stixCoreObject: unknown;
  isContainer?: boolean;
}

const StixCoreObjectContentRoot: FunctionComponent<StixCoreObjectContentRootProps> = ({
  stixCoreObject, isContainer = false,
}) => {
  const { pathname } = useLocation();
  const currentMode = pathname.endsWith('/mapping') ? 'mapping' : 'content';
  const modes = isContainer ? ['content', 'mapping'] : [];
  return (
    <>
      <StixCoreObjectContentHeader
        currentMode={currentMode}
        modes={modes}
      />
      <Routes>
        <Route
          path="/mapping"
          element={
            <ContainerContent
              containerData={stixCoreObject}
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
