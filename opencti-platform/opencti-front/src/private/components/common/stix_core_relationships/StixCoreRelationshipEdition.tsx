import React from 'react';
import { graphql } from 'react-relay';
import Drawer from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from 'src/components/Theme';
import { StixCoreRelationshipEditionOverviewQuery } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipEditionOverviewQuery.graphql';
import StixCoreRelationshipEditionOverview, { stixCoreRelationshipEditionOverviewQuery } from './StixCoreRelationshipEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  drawerPaperInGraph: {
    minHeight: '100vh',
    width: '30%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

export const stixCoreRelationshipEditionDeleteMutation = graphql`
  mutation StixCoreRelationshipEditionDeleteMutation($id: ID!) {
    stixCoreRelationshipEdit(id: $id) {
      delete
    }
  }
`;

type StixCoreRelationshipEditionContainerProps = {
  stixCoreRelationshipId: string;
  open: boolean;
  inGraph: boolean;
  noStoreUpdate: boolean;
  handleDelete: () => void;
  handleClose: () => void;
};

type StixCoreRelationshipEditionProps = {
  stixCoreRelationshipId: string;
  noStoreUpdate: boolean;
  handleDelete: () => void;
  handleClose: () => void;
};

const StixCoreRelationshipEdition = ({
  stixCoreRelationshipId,
  handleClose,
  handleDelete,
  noStoreUpdate,
}: StixCoreRelationshipEditionProps) => {
  const queryRef = useQueryLoading<StixCoreRelationshipEditionOverviewQuery>(stixCoreRelationshipEditionOverviewQuery, {
    id: stixCoreRelationshipId,
  });

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
      <StixCoreRelationshipEditionOverview
        queryRef={queryRef}
        handleClose={handleClose}
        handleDelete={handleDelete}
        noStoreUpdate={noStoreUpdate}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inline} />
  );
};

const StixCoreRelationshipEditionContainer = (props: StixCoreRelationshipEditionContainerProps) => {
  const classes = useStyles();
  const {
    open,
    inGraph,
    stixCoreRelationshipId,
    handleClose,
    handleDelete,
    noStoreUpdate,
  } = props;

  return (
    <Drawer
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: inGraph ? classes.drawerPaperInGraph : classes.drawerPaper }}
      onClose={handleClose}
    >
      {open && (
        <StixCoreRelationshipEdition
          stixCoreRelationshipId={stixCoreRelationshipId}
          handleDelete={handleDelete}
          noStoreUpdate={noStoreUpdate}
          handleClose={handleClose}
        />
      )}
    </Drawer>
  );
};

export default StixCoreRelationshipEditionContainer;
