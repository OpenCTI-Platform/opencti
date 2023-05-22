import { Edit } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { useMutation } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseRfiEditionContainerCaseQuery } from './__generated__/CaseRfiEditionContainerCaseQuery.graphql';
import CaseRfiEditionContainer, { caseRfiEditionQuery } from './CaseRfiEditionContainer';
import { caseRfiEditionOverviewFocus } from './CaseRfiEditionOverview';

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

const CaseRfiEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [commit] = useMutation(caseRfiEditionOverviewFocus);
  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    commit({
      variables: {
        id: caseId,
        input: { focusOn: '' },
      },
    });
    setOpen(false);
  };
  const queryRef = useQueryLoading<CaseRfiEditionContainerCaseQuery>(
    caseRfiEditionQuery,
    { id: caseId },
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
            <CaseRfiEditionContainer
              queryRef={queryRef}
              handleClose={handleClose}
            />
          </React.Suspense>
        )}
      </Drawer>
    </div>
  );
};

export default CaseRfiEdition;
