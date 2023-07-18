import React from 'react';
import { graphql } from 'react-relay';
import Drawer from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreRelationshipEditionOverview, {
  stixCoreRelationshipEditionOverviewQuery,
} from './StixCoreRelationshipEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const useStyles = makeStyles((theme) => ({
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
}));

export const stixCoreRelationshipEditionDeleteMutation = graphql`
  mutation StixCoreRelationshipEditionDeleteMutation($id: ID!) {
    stixCoreRelationshipEdit(id: $id) {
      delete
    }
  }
`;

const StixCoreRelationshipEdition = ({
  stixCoreRelationshipId,
  open,
  handleClose,
  handleDelete,
  noStoreUpdate,
}) => {
  const classes = useStyles();
  const queryRef = useQueryLoading(stixCoreRelationshipEditionOverviewQuery, {
    id: stixCoreRelationshipId,
  });
  return (
    <Drawer
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawerPaper }}
      onClose={handleClose}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixCoreRelationshipEditionOverview
            queryRef={queryRef}
            handleClose={handleClose}
            handleDelete={
              typeof handleDelete === 'function' ? handleDelete : null
            }
            noStoreUpdate={noStoreUpdate}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </Drawer>
  );
};

export default StixCoreRelationshipEdition;
