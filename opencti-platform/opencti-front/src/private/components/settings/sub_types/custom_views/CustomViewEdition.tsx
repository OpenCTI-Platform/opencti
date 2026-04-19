import { Suspense } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { Stack } from '@mui/material';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../../components/Loader';
import DashboardTimeFilters from '../../../../../components/dashboard/DashboardTimeFilters';
import DashboardContent from '../../../../../components/dashboard/DashboardContent';
import type { useCustomViewDashboardEdit_Query } from './__generated__/useCustomViewDashboardEdit_Query.graphql';
import CustomViewEditionHeader from './CustomViewEditionHeader';
import useCustomViewDashboardEdit, { customViewQuery } from './useCustomViewDashboardEdit';

interface CustomViewEditionComponentProps {
  queryRef: PreloadedQuery<useCustomViewDashboardEdit_Query>;
}

const CustomViewEditionComponent = ({ queryRef }: CustomViewEditionComponentProps) => {
  const { customView } = usePreloadedQuery(customViewQuery, queryRef);
  const helpers = useCustomViewDashboardEdit({ customView });
  const { handleAddWidget, handleImportWidget, handleDateChange, config } = helpers;
  if (!customView) {
    return <ErrorNotFound />;
  }
  return (
    <Stack gap={2}>
      <Stack gap={1}>
        <CustomViewEditionHeader
          data={customView}
          onCreateWidget={handleAddWidget}
          onImportWidget={handleImportWidget}
        />
        <DashboardTimeFilters
          currentUserAccessRight="edit"
          config={config}
          handleDateChange={handleDateChange}
        />
      </Stack>
      <DashboardContent
        helpers={helpers}
        dashboardEntity={customView}
        isEditable={true}
      />
    </Stack>
  );
};

const CustomViewEdition = () => {
  const { customViewId } = useParams<{ customViewId?: string }>();
  if (!customViewId) {
    return <ErrorNotFound />;
  }

  const queryRef = useQueryLoading<useCustomViewDashboardEdit_Query>(
    customViewQuery,
    {
      id: customViewId,
    },
  );

  return (
    <Suspense fallback={<Loader />}>
      {queryRef && <CustomViewEditionComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default CustomViewEdition;
