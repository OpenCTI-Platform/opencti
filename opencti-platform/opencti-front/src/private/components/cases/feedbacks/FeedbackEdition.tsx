import React, { FunctionComponent, useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { feedbackEditionOverviewFocus } from './FeedbackEditionOverview';
import { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import FeedbackEditionContainer, {
  feedbackEditionQuery,
} from './FeedbackEditionContainer';
import { FeedbackEditionContainerQuery } from './__generated__/FeedbackEditionContainerQuery.graphql';

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

const FeedbackEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [commit] = useMutation(feedbackEditionOverviewFocus);
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
  const queryRef = useQueryLoading<FeedbackEditionContainerQuery>(
    feedbackEditionQuery,
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
            <FeedbackEditionContainer
              queryRef={queryRef}
              handleClose={handleClose}
            />
          </React.Suspense>
        )}
      </Drawer>
    </div>
  );
};

export default FeedbackEdition;
