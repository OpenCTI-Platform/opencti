import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import IndicatorEditionContainer from './IndicatorEditionContainer';
import { indicatorEditionOverviewFocus } from './IndicatorEditionOverview';
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

export const indicatorEditionQuery = graphql`
  query IndicatorEditionContainerQuery($id: String!) {
    indicator(id: $id) {
      ...IndicatorEditionContainer_indicator
    }
  }
`;

const IndicatorEdition = ({ indicatorId }) => {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    commitMutation({
      mutation: indicatorEditionOverviewFocus,
      variables: {
        id: indicatorId,
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
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleClose}
        >
          <QueryRenderer
            query={indicatorEditionQuery}
            variables={{ id: indicatorId }}
            render={({ props }) => {
              if (props) {
                return (
                  <IndicatorEditionContainer indicator={props.indicator} handleClose={handleClose} />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Drawer>
      </div>
  );
};

export default IndicatorEdition;
