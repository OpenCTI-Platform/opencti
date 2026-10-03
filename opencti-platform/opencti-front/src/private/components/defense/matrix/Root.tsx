import React, { lazy, Suspense } from 'react';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { boundaryWrapper } from '../../Error';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import Loader from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { PATH_DEFENSE_GAPS, PATH_DEFENSE_MATRIX } from '@components/common/routes/paths';
import DefenseCoverageDashboardButton from './DefenseCoverageDashboardButton';

const DefenseMatrix = lazy(() => import('./DefenseMatrix'));
const DefenseGaps = lazy(() => import('./DefenseGaps'));

/**
 * Defense > Defense matrix: the matrix and the gap backlog of the threat-informed defense, as two tabs.
 */
const RootDefenseMatrix = () => {
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const currentTab = location.pathname.startsWith(PATH_DEFENSE_GAPS) ? 'gaps' : 'matrix';
  return (
    <div data-testid="defense-matrix-page">
      <PageContainer withGap>
        <Breadcrumbs noMargin elements={[{ label: t_i18n('Defense') }, { label: t_i18n('Defense matrix'), current: true }]} />
        <Tabs value={currentTab} panels="external">
          <TabsList actions={<DefenseCoverageDashboardButton />}>
            <TabsTrigger value="matrix" asChild>
              <Link to={PATH_DEFENSE_MATRIX} data-testid="defense-tab-matrix">{t_i18n('Matrix')}</Link>
            </TabsTrigger>
            <TabsTrigger value="gaps" asChild>
              <Link to={PATH_DEFENSE_GAPS} data-testid="defense-tab-gaps">{t_i18n('Gaps')}</Link>
            </TabsTrigger>
          </TabsList>
        </Tabs>
        <Suspense fallback={<Loader />}>
          <Routes>
            <Route path="/" element={boundaryWrapper(DefenseMatrix)} />
            <Route path="/gaps" element={boundaryWrapper(DefenseGaps)} />
            <Route path="*" element={<Navigate to={PATH_DEFENSE_MATRIX} replace />} />
          </Routes>
        </Suspense>
      </PageContainer>
    </div>
  );
};

export default RootDefenseMatrix;
