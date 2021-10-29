import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import Avatar from '@material-ui/core/Avatar';
import { Close } from '@material-ui/icons';
import ListItem from '@material-ui/core/ListItem';
import ListItemAvatar from '@material-ui/core/ListItemAvatar';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import List from '@material-ui/core/List';
import inject18n from '../../../../components/i18n';
import StatusCreation from './StatusCreation';
import StatusPopover from './StatusPopover';
import { hexToRGB } from '../../../../utils/Colors';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
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
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

class SubTypeEditionContainer extends Component {
  render() {
    const {
      t, classes, handleClose, subType,
    } = this.props;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
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
