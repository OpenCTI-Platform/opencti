import { Suspense, useMemo, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import Box from '@mui/material/Box';
import { Stack } from '@mui/material';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../../components/Loader';
import DashboardTimeFilters from '../../../../../components/dashboard/DashboardTimeFilters';
import DashboardContent from '../../../../../components/dashboard/DashboardContent';
import type { useCustomViewDashboardEdit_Query } from './__generated__/useCustomViewDashboardEdit_Query.graphql';
import CustomViewEditionHeader from './CustomViewEditionHeader';
import useCustomViewDashboardEdit, { customViewQuery } from './useCustomViewDashboardEdit';
import CustomViewPreviewEntitySelector from './CustomViewPreviewEntitySelector';
import CustomViewEditionMissingContextEntityFiller from './CustomViewEditionMissingContextEntityFiller';

interface CustomViewEditionComponentProps {
  queryRef: PreloadedQuery<useCustomViewDashboardEdit_Query>;
  entityType: string;
}

const CustomViewEditionComponent = ({ queryRef, entityType }: CustomViewEditionComponentProps) => {
  const { customView } = usePreloadedQuery(customViewQuery, queryRef);
  const helpers = useCustomViewDashboardEdit({ customView });
  const { handleAddWidget, handleImportWidget, handleDateChange, config } = helpers;
  const [previewEntityId, setPreviewEntityId] = useState<string | null>(null);
  const handlePreviewEntityChange = (id: string | null) => {
    setPreviewEntityId(id);
  };
  const context = useMemo(() => ({
    kind: 'custom-view' as const,
    customViewTargetEntityType: entityType,
    customViewTargetEntityId: previewEntityId ?? undefined,
    previewMode: Boolean(previewEntityId),
    missingContextEntityFiller: <CustomViewEditionMissingContextEntityFiller />,
  }), [entityType, previewEntityId]);
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
          context={context}
        />
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <DashboardTimeFilters
            config={config}
            handleDateChange={handleDateChange}
          />
          <CustomViewPreviewEntitySelector type={entityType} onPreviewEntityChange={handlePreviewEntityChange} />
        </Box>
      </Stack>
      <DashboardContent
        helpers={helpers}
        entity={customView}
        isEditable={true}
        context={context}
      />
    </Stack>
  );
};

interface CustomViewEditionProps {
  entityType: string;
}

const CustomViewEdition = ({ entityType }: CustomViewEditionProps) => {
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
      {queryRef && <CustomViewEditionComponent queryRef={queryRef} entityType={entityType} />}
    </Suspense>
  );
};

export default CustomViewEdition;
