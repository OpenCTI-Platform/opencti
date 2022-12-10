import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useMutation } from 'react-relay';
import RegionEditionContainer, { regionEditionQuery } from './RegionEditionContainer';
import { regionEditionOverviewFocus } from './RegionEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { Theme } from '../../../../components/Theme';
import { RegionEditionContainerQuery } from './__generated__/RegionEditionContainerQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 400,
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

const RegionEdition = ({ regionId }: { regionId: string }) => {
  const classes = useStyles();
  const [open, setOpen] = useState<boolean>(false);
  const [commit] = useMutation(regionEditionOverviewFocus);

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    commit({
      variables: {
        id: regionId,
        input: { focusOn: '' },
      },
    });
    setOpen(false);
  };

  const queryRef = useQueryLoading<RegionEditionContainerQuery>(regionEditionQuery, { id: regionId });

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
            <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
              <RegionEditionContainer
                queryRef={queryRef}
                handleClose={handleClose}
              />
            </React.Suspense>
          )}
        </Drawer>
      </div>
  );
};

export default RegionEdition;
