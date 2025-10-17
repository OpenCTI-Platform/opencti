import React from 'react';
import { Route, Routes } from 'react-router-dom';
import RestrictedEntities from './RestrictedEntities';
import RestrictedDrafts from './RestrictedDrafts';
import useHelper from '../../../../utils/hooks/useHelper';
import ManagementMenu from '../ManagementMenu';
import PageContainer from '../../../../components/PageContainer';

const RestrictionRoot = () => {
  const { isFeatureEnable } = useHelper();
  const isRightMenuManagementEnable = isFeatureEnable('DATA_MANAGEMENT_RIGHT_MENU');

  return (
    <div data-testid="data-management-page" style={{ height: '100%' }}>
      {isRightMenuManagementEnable && (
        <ManagementMenu />
      )}
      <PageContainer
        withGap
        withRightMenu={isRightMenuManagementEnable}
        style={{ height: '100%' }}
      >
        <Routes>
          <Route path="/restricted" element={<RestrictedEntities />} />
          <Route path="/drafts" element={<RestrictedDrafts />} />
        </Routes>
      </PageContainer>
    </div>
  );
};

export default RestrictionRoot;
