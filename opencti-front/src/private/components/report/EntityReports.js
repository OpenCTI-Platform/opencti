import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { Description } from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';
import truncate from '../../../utils/String';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
  item: {
    height: 60,
    minHeight: 60,
    maxHeight: 60,
    transition: 'background-color 0.1s ease',
    paddingRight: 0,
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
});

const inlineStyles = {
  itemDate: {
    fontSize: 11,
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    textAlign: 'right',
    color: '#ffffff',
  },
};

class EntityReportsComponent extends Component {
  render() {
    const { t, classes } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Last reports')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <List>
            <ListItem
              dense={true}
              classes={{ default: classes.item }}
              divider={true}
              component={Link}
              to={'/dashboard/reports/'}
            >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <Description/>
              </ListItemIcon>
              <ListItemText primary={truncate('dsqd sdqsd qsdqs dqsd qsd qsdqs ', 120)} secondary={truncate('dfsfds fdsf sdf sdfsdfdsf sdf sdf sdf sdfsd fdsf sdfsdf sdfs fdsdf sdf', 150)}/>
              <div style={{ minWidth: 100 }}>
                <ItemMarking label='TLP:RED' position='normal'/>
              </div>
              <div style={inlineStyles.itemDate}>28 mai 2018</div>
            </ListItem>
            <ListItem
              dense={true}
              classes={{ default: classes.item }}
              divider={true}
              component={Link}
              to={'/dashboard/reports/'}
            >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <Description/>
              </ListItemIcon>
              <ListItemText primary={truncate('dsqd sdqsd qsdqs dqsd qsd qsdqs ', 120)} secondary={truncate('dfsfds fdsf sdf sdfsdfdsf sdf sdf sdf sdfsd fdsf sdfsdf sdfs fdsdf sdf', 150)}/>
              <div style={{ minWidth: 100 }}>
                <ItemMarking label='TLP:RED' position='normal'/>
              </div>
              <div style={inlineStyles.itemDate}>28 mai 2018</div>
            </ListItem>
            <ListItem
              dense={true}
              classes={{ default: classes.item }}
              divider={true}
              component={Link}
              to={'/dashboard/reports/'}
            >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <Description/>
              </ListItemIcon>
              <ListItemText primary={truncate('dsqd sdqsd qsdqs dqsd qsd qsdqs ', 120)} secondary={truncate('dfsfds fdsf sdf sdfsdfdsf sdf sdf sdf sdfsd fdsf sdfsdf sdfs fdsdf sdf', 150)}/>
              <div style={{ minWidth: 100 }}>

              </div>
              <div style={inlineStyles.itemDate}>28 mai 2018</div>
            </ListItem>
            <ListItem
              dense={true}
              classes={{ default: classes.item }}
              divider={true}
              component={Link}
              to={'/dashboard/reports/'}
            >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <Description/>
              </ListItemIcon>
              <ListItemText primary={truncate('dsqd sdqsd qsdqs dqsd qsd qsdqs ', 120)} secondary={truncate('dfsfds fdsf sdf sdfsdfdsf sdf sdf sdf sdfsd fdsf sdfsdf sdfs fdsdf sdf', 150)}/>
              <div style={{ minWidth: 100 }}>
                <ItemMarking label='TLP:RED' position='normal'/>
              </div>
              <div style={inlineStyles.itemDate}>28 mai 2018</div>
            </ListItem>
            <ListItem
              dense={true}
              classes={{ default: classes.item }}
              divider={true}
              component={Link}
              to={'/dashboard/reports/'}
            >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <Description/>
              </ListItemIcon>
              <ListItemText primary={truncate('dsqd sdqsd qsdqs dqsd qsd qsdqs ', 120)} secondary={truncate('dfsfds fdsf sdf sdfsdfdsf sdf sdf sdf sdfsd fdsf sdfsdf sdfs fdsdf sdf', 150)}/>
              <div style={{ minWidth: 100 }}>
                <ItemMarking label='TLP:RED' position='normal'/>
              </div>
              <div style={inlineStyles.itemDate}>28 mai 2018</div>
            </ListItem>
          </List>
        </Paper>
      </div>
    );
  }
}

EntityReportsComponent.propTypes = {
  reports: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const EntityReports = createFragmentContainer(EntityReportsComponent, {
  reports: graphql`
      fragment EntityReports_reports on Malware {
          id,
          name,
          description,
          created,
          modified
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(EntityReports);
