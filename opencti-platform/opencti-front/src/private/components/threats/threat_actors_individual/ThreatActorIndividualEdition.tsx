import { Edit } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import makeStyles from '@mui/styles/makeStyles';
import React, { useState } from 'react';
import { useMutation } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ThreatActorIndividualEditionContainer, {
  ThreatActorIndividualEditionQuery,
} from './ThreatActorIndividualEditionContainer';
import {
  ThreatActorIndividualEditionOverviewFocusMutation,
} from './__generated__/ThreatActorIndividualEditionOverviewFocusMutation.graphql';
import {
  ThreatActorIndividualEditionContainerQuery,
} from './__generated__/ThreatActorIndividualEditionContainerQuery.graphql';
import { ThreatActorIndividualEditionOverviewFocus } from './ThreatActorIndividualEditionOverview';

const useStyles = makeStyles<Theme>((theme) => ({
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
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

const ThreatActorIndividualEdition = ({ threatActorIndividualId }: { threatActorIndividualId: string }) => {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [commit] = useMutation<ThreatActorIndividualEditionOverviewFocusMutation>(ThreatActorIndividualEditionOverviewFocus);
  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    commit({
      variables: {
        id: threatActorIndividualId,
        input: { focusOn: '' },
      },
    });
    setOpen(false);
  };
  const queryRef = useQueryLoading<ThreatActorIndividualEditionContainerQuery>(
    ThreatActorIndividualEditionQuery,
    { id: threatActorIndividualId },
  );
  return (
    <div>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Edit"
        className={classes.editButton}
      >
        <Edit />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        {queryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <ThreatActorIndividualEditionContainer
              queryRef={queryRef}
              handleClose={handleClose}
            />
          </React.Suspense>
        )}
      </Drawer>
    </div>
  );
};

export default ThreatActorIndividualEdition;
