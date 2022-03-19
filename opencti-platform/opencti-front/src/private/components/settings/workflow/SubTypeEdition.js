import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Avatar from '@mui/material/Avatar';
import { Close } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import ListItemAvatar from '@mui/material/ListItemAvatar';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import List from '@mui/material/List';
import inject18n from '../../../../components/i18n';
import StatusCreation from './StatusCreation';
import StatusPopover from './StatusPopover';
import { hexToRGB } from '../../../../utils/Colors';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

class SubTypeEditionContainer extends Component {
  render() {
    const { t, classes, handleClose, subType } = this.props;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {`${t('Workflow of')} ${subType.label}`}
          </Typography>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <List
            component="nav"
            aria-labelledby="nested-list-subheader"
            className={classes.root}
          >
            {subType.statuses.edges.map((statusEdge) => {
              const status = statusEdge.node;
              return (
                <ListItem
                  key={status.id}
                  classes={{ root: classes.item }}
                  divider={true}
                >
                  <ListItemAvatar>
                    <Avatar
                      variant="square"
                      style={{
                        color: status.template.color,
                        borderColor: status.template.color,
                        backgroundColor: hexToRGB(status.template.color),
                      }}
                    >
                      {status.order}
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText primary={t(`status_${status.template.name}`)} />
                  <ListItemSecondaryAction>
                    <StatusPopover
                      subTypeId={subType.id}
                      statusId={status.id}
                    />
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>
          <StatusCreation subTypeId={subType.id} display={true} />
        </div>
      </div>
    );
  }
}

SubTypeEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  subType: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const SubTypeEditionFragment = createFragmentContainer(
  SubTypeEditionContainer,
  {
    subType: graphql`
      fragment SubTypeEdition_subType on SubType {
        id
        label
        statuses {
          edges {
            node {
              id
              order
              template {
                name
                color
              }
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(SubTypeEditionFragment);
