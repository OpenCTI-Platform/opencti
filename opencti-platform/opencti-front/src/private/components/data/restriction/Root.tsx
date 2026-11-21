import { Navigate, Route, Routes } from 'react-router';
import PageContainer from '../../../../components/PageContainer';
import RestrictedDrafts from './RestrictedDrafts';
import RestrictedEntities from './RestrictedEntities';
import RestrictionMenu from './RestrictionMenu';
import EntryGuard from '../../nav/EntryGuard';

const RestrictionRoot = () => {
  return (
    <div data-testid="data-management-page" style={{ height: '100%' }}>
      <RestrictionMenu />
      <PageContainer
        withGap
        withRightMenu
        style={{ height: '100%' }}
      >
        <Routes>
          <Route
            path="/drafts"
            element={(
              <EntryGuard path="/dashboard/data/restriction/drafts">
                <RestrictedDrafts />
              </EntryGuard>
            )}
          />
          <Route
            path="/restricted"
            element={(
              <EntryGuard path="/dashboard/data/restriction/restricted" placeholder={<Navigate to="/dashboard/data/restriction/drafts" replace={true} />}>
                <RestrictedEntities />
              </EntryGuard>
            )}
          />
          {/* The `/restricted` guard sends users who cannot open it (no EE, no capability) to `/drafts`. */}
          <Route index element={<Navigate to="/dashboard/data/restriction/restricted" replace={true} />} />
        </Routes>
      </PageContainer>
    </div>
  );
};

export default RestrictionRoot;
