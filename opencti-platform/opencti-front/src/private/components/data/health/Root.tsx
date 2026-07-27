import { Navigate, Route, Routes } from 'react-router-dom';
import PageContainer from '../../../../components/PageContainer';
import HealthMenu from './HealthMenu';
import Operations from './Operations';

const HealthRoot = () => {
  return (
    <div data-testid="data-health-page" style={{ height: '100%' }}>
      <HealthMenu />
      <PageContainer
        withGap
        withRightMenu
        style={{ height: '100%' }}
      >
        <Routes>
          <Route path="/operations" element={<Operations />} />
          <Route index element={<Navigate to="/dashboard/data/health/operations" replace={true} />} />
        </Routes>
      </PageContainer>
    </div>
  );
};

export default HealthRoot;
