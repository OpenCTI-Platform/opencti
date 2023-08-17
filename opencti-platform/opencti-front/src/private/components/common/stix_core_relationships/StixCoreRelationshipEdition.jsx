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

const StixCoreRelationshipEdition = ({
  stixCoreRelationshipId,
  open,
  handleClose,
  handleDelete,
  noStoreUpdate,
  inGraph,
}) => {
  const classes = useStyles();
  const queryRef = useQueryLoading(stixCoreRelationshipEditionOverviewQuery, {
    id: stixCoreRelationshipId,
  });
  const renderClassic = () => {
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

  const renderInGraph = () => {
    return (
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaperInGraph }}
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
  if (inGraph) {
    // in a graph bar
    return renderInGraph();
  }
  return renderClassic();
};

export default StixCoreRelationshipEdition;
