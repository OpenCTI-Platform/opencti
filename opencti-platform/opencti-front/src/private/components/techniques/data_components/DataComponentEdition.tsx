import React, { FunctionComponent, useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import DataComponentEditionContainer, { dataComponentEditionQuery } from './DataComponentEditionContainer';
import { dataComponentEditionOverviewFocus } from './DataComponentEditionOverview';
import { Theme } from '../../../../components/Theme';
import { DataComponentEditionContainerQuery } from './__generated__/DataComponentEditionContainerQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

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

const DataComponentEdition: FunctionComponent<{ dataComponentId: string }> = ({ dataComponentId }) => {
  const classes = useStyles();

  const [open, setOpen] = useState(false);
  const [commit] = useMutation(dataComponentEditionOverviewFocus);
  const handleOpen = () => setOpen(true);

  const handleClose = () => {
    commit({
      variables: {
        id: dataComponentId,
        input: { focusOn: '' },
      },
    });
    setOpen(false);
  };

  const queryRef = useQueryLoading<DataComponentEditionContainerQuery>(dataComponentEditionQuery, { id: dataComponentId });

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
              <DataComponentEditionContainer
                queryRef={queryRef}
                handleClose={handleClose}
              />
            </React.Suspense>
          )}
        </Drawer>
      </div>
  );
};

export default DataComponentEdition;
