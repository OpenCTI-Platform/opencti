import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import InfrastructureEditionContainer, {
  infrastructureEditionContainerQuery,
} from './InfrastructureEditionContainer';
import { infrastructureEditionOverviewFocus } from './InfrastructureEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';

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

const InfrastructureEdition = ({ infrastructureId }: { infrastructureId: string }) => {
  const classes = useStyles();
  const [open, setOpen] = useState<boolean>(false);
  const [commit] = useMutation(infrastructureEditionOverviewFocus);
  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    commit({
      variables: {
        id: infrastructureId,
        input: { focusOn: '' },
      },
    });
    setOpen(false);
  };

  const queryRef = useQueryLoading<InfrastructureEditionContainerQuery>(
    infrastructureEditionContainerQuery,
    { id: infrastructureId },
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
        sx={{ zIndex: 1202 }}
        elevation={1}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <InfrastructureEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
        )}
      </Drawer>
    </div>
  );
};

export default InfrastructureEdition;
