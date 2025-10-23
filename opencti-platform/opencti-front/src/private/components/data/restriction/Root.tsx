import { Navigate, Route, Routes } from 'react-router-dom';
import PageContainer from '../../../../components/PageContainer';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import RestrictedDrafts from './RestrictedDrafts';
import RestrictedEntities from './RestrictedEntities';
import RestrictionMenu from './RestrictionMenu';

const RestrictionRoot = () => {
  const isEnterpriseEdition = useEnterpriseEdition();

  return (
    <div data-testid="data-management-page" style={{ height: '100%' }}>
      <RestrictionMenu />
      <PageContainer
        withGap
        withRightMenu
        style={{ height: '100%' }}
      >
        <Routes>
          <Route path="/drafts" element={<RestrictedDrafts />} />
          {isEnterpriseEdition && <Route path="/restricted" element={<RestrictedEntities />} />}
          <Route index element={<Navigate to={isEnterpriseEdition ? '/dashboard/data/restriction/restricted' : '/dashboard/data/restriction/drafts'} replace={true} />} />
        </Routes>
      </PageContainer>
    </div>
  );
};

export default RestrictionRoot;
