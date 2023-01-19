import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import makeStyles from '@mui/styles/makeStyles';
import { Edit } from '@mui/icons-material';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SubTypeWorkflow, { subTypeWorkflowEditionQuery } from './SubTypeWorkflow';
import { SubTypeWorkflowEditionQuery } from './__generated__/SubTypeWorkflowEditionQuery.graphql';

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
}));

const SubTypeStatusPopover = ({ subTypeId }: { subTypeId: string }) => {
  const classes = useStyles();

  const queryRef = useQueryLoading<SubTypeWorkflowEditionQuery>(subTypeWorkflowEditionQuery, { id: subTypeId });
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);

  return (
    <>
      <IconButton
        color="secondary"
        aria-label="Workflow"
        onClick={handleOpenUpdate}
        aria-haspopup="true"
        size="large"
      >
        <Edit fontSize="small" />
      </IconButton>
      <Drawer
        open={displayUpdate}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseUpdate}
      >
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <SubTypeWorkflow
              queryRef={queryRef}
              handleClose={handleCloseUpdate}
            />
          </React.Suspense>
        )}
      </Drawer>
    </>
  );
};

export default SubTypeStatusPopover;
