import React from 'react';
import { graphql } from 'react-relay';
import Drawer from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import StixSightingRelationshipEditionOverview, {
  stixSightingRelationshipEditionOverviewQuery,
} from './StixSightingRelationshipEditionOverview';
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

export const stixSightingRelationshipEditionDeleteMutation = graphql`
  mutation StixSightingRelationshipEditionDeleteMutation($id: ID!) {
    stixSightingRelationshipEdit(id: $id) {
      delete
    }
  }
`;

const StixSightingRelationshipEditionInner = ({ stixSightingRelationshipId, open, handleClose, handleDelete, inferred, noStoreUpdate, inGraph }) => {
  const classes = useStyles();
  const queryRef = useQueryLoading(stixSightingRelationshipEditionOverviewQuery, { id: stixSightingRelationshipId });

  const renderInGraph = () => {
    return (
      <Drawer open={open}
              anchor="right"
              elevation={1}
              sx={{ zIndex: 1202 }}
              classes={{ paper: classes.drawerPaperInGraph }}
              onClose={handleClose}>
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <StixSightingRelationshipEditionOverview
              queryRef={queryRef}
              handleClose={handleClose}
              handleDelete={typeof handleDelete === 'function' ? handleDelete : null}
              inferred={inferred}
              noStoreUpdate={noStoreUpdate}
            />
          </React.Suspense>
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
              onClose={handleClose}>
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <StixSightingRelationshipEditionOverview
              queryRef={queryRef}
              handleClose={handleClose}
              handleDelete={typeof handleDelete === 'function' ? handleDelete : null}
              inferred={inferred}
              noStoreUpdate={noStoreUpdate}
            />
          </React.Suspense>
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

// Workaround to prevent direct loading
const StixSightingRelationshipEdition = ({ stixSightingRelationshipId, open, handleClose, handleDelete, inferred, noStoreUpdate, inGraph }) => {
  if (stixSightingRelationshipId && open) {
    return <StixSightingRelationshipEditionInner open={open} stixSightingRelationshipId={stixSightingRelationshipId}
                                                 handleClose={handleClose} handleDelete={handleDelete}
                                                 inferred={inferred} noStoreUpdate={noStoreUpdate} inGraph={inGraph} />;
  }
  return <></>;
};

export default StixSightingRelationshipEdition;
