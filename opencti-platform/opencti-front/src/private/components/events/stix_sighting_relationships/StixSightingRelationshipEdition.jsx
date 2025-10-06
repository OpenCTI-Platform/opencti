import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { Drawer } from '@components';
import StixSightingRelationshipEditionOverview, { stixSightingRelationshipEditionOverviewQuery } from './StixSightingRelationshipEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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

export const stixSightingRelationshipEditionDeleteMutation = graphql`
  mutation StixSightingRelationshipEditionDeleteMutation($id: ID!) {
    stixSightingRelationshipEdit(id: $id) {
      delete
    }
  }
`;

const StixSightingRelationshipEdition = ({ stixSightingRelationshipId, open, handleClose, inferred, noStoreUpdate, inGraph }) => {
  const classes = useStyles();
  const queryRef = useQueryLoading(stixSightingRelationshipEditionOverviewQuery, { id: stixSightingRelationshipId });

  const renderInGraph = () => {
    return (
      <Drawer open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaperInGraph }}
        onClose={handleClose}
      >
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
            <StixSightingRelationshipEditionOverview
              queryRef={queryRef}
              handleClose={handleClose}
              inferred={inferred}
              noStoreUpdate={noStoreUpdate}
            />
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.inline} />
        )}
      </Drawer>
    );
  };

  const renderClassic = () => {
    return (
      <Drawer open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
            <StixSightingRelationshipEditionOverview
              queryRef={queryRef}
              handleClose={handleClose}
              inferred={inferred}
              noStoreUpdate={noStoreUpdate}
            />
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.inline} />
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

export default StixSightingRelationshipEdition;
