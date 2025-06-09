import React, { FunctionComponent } from 'react';
import Drawer from '@mui/material/Drawer';
import { useTheme } from '@mui/styles';
import {
  StixNestedRefRelationshipEditionOverviewQuery,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipEditionOverviewQuery.graphql';
import StixNestedRefRelationshipEditionOverview, { stixNestedRefRelationshipEditionQuery } from './StixNestedRefRelationshipEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

interface StixNestedRefRelationshipEditionProps {
  stixNestedRefRelationshipId: string,
  open: boolean,
  handleClose?: () => void,
}

const StixNestedRefRelationshipEdition: FunctionComponent<StixNestedRefRelationshipEditionProps> = ({
  stixNestedRefRelationshipId,
  open,
  handleClose,
}) => {
  const theme = useTheme<Theme>();
  const queryRef = useQueryLoading<StixNestedRefRelationshipEditionOverviewQuery>(
    stixNestedRefRelationshipEditionQuery,
    { id: stixNestedRefRelationshipId },
  );
  return (
    <Drawer
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      style={{
        minHeight: '100vh',
        width: '30%',
        position: 'fixed',
        overflow: 'auto',
        transition: theme.transitions.create('width', {
          easing: theme.transitions.easing.sharp,
          duration: theme.transitions.duration.enteringScreen,
        }),
        padding: 0,
      }}
      onClose={handleClose}
    >
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <StixNestedRefRelationshipEditionOverview
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </Drawer>
  );
};

export default StixNestedRefRelationshipEdition;
