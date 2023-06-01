import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import GroupingEditionContainer from './GroupingEditionContainer';
import { groupingEditionOverviewFocus } from './GroupingEditionOverview';
import Loader from '../../../../components/Loader';

const useStyles = makeStyles((theme) => ({
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

export const groupingEditionQuery = graphql`
  query GroupingEditionContainerQuery($id: String!) {
    grouping(id: $id) {
      ...GroupingEditionContainer_grouping
    }
  }
`;

const GroupingEdition = ({ groupingId }) => {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    commitMutation({
      mutation: groupingEditionOverviewFocus,
      variables: {
        id: groupingId,
        input: { focusOn: '' },
      },
    });
    setOpen(false);
  };
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
        <QueryRenderer
          query={groupingEditionQuery}
          variables={{ id: groupingId }}
          render={({ props }) => {
            if (props) {
              return (
                <GroupingEditionContainer
                  grouping={props.grouping}
                  handleClose={handleClose}
                />
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
      </Drawer>
    </div>
  );
};

export default GroupingEdition;
