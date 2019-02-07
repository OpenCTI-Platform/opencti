import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import MenuList from '@material-ui/core/MenuList';
import ListSubheader from '@material-ui/core/ListSubheader';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Checkbox from '@material-ui/core/Checkbox';
import Collapse from '@material-ui/core/Collapse';
import Drawer from '@material-ui/core/Drawer';
import { Public, ExpandLess, ExpandMore } from '@material-ui/icons';
import { Diamond } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  subheader: {
    paddingLeft: 15,
  },
  nested: {
    paddingLeft: theme.spacing.unit * 4,
  },
  listIcon: {
    marginRight: 5,
  },
  listText: {
    paddingRight: 5,
  },
  toolbar: theme.mixins.toolbar,
});

const victimologyRightBarThreatActorsQuery = graphql`
    query VictimologyRightBarThreatActorsQuery {
        threatActors {
            edges {
                node {
                    id
                    name
                    description
                }
            }
        }
    }
`;

const victimologyRightBarIntrusionSetsQuery = graphql`
    query VictimologyRightBarIntrusionSetsQuery {
        intrusionSets {
            edges {
                node {
                    id
                    name
                    description
                }
            }
        }
    }
`;

class VictimologyRightBar extends Component {
  constructor(props) {
    super(props);
    this.state = { threatActorOpen: true };
  }

  handleThreatActorToggle() {
    this.setState({ threatActorOpen: !this.state.threatActorOpen });
  }

  render() {
    const { t, classes } = this.props;
    return (
      <Drawer variant='permanent' anchor='right' classes={{ paper: classes.drawerPaper }}>
        <div className={classes.toolbar}/>
        <MenuList component='nav' classes={{ root: classes.menuList }} subheader={<ListSubheader classes={{ root: classes.subheader }} color='primary'>{t('Origins of the targeting')}</ListSubheader>}>
          <MenuItem onClick={this.handleThreatActorToggle.bind(this)} dense={true}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <Public/>
            </ListItemIcon>
            <ListItemText primary={t('Threat actors')} classes={{ root: classes.listText }}/>
            {this.state.threatActorOpen ? <ExpandLess/> : <ExpandMore/>}
          </MenuItem>
          <Collapse in={this.state.threatActorOpen} timeout='auto' unmountOnExit={true}>
            <QueryRenderer
              query={victimologyRightBarThreatActorsQuery}
              render={({ props }) => {
                if (props && props.threatActors) {
                  return (
                    <MenuList component='div' disablePadding={true}>
                      {props.threatActors.edges.map((threatActorEdge) => {
                        const threatActor = threatActorEdge.node;
                        return (
                          <MenuItem
                            key={threatActor.id}
                            className={classes.nested}
                            dense={true}
                          >
                            <Checkbox
                              tabIndex={-1}
                              disableRipple
                            />
                            <ListItemText primary={threatActor.name}/>
                          </MenuItem>
                        );
                      })}
                    </MenuList>
                  );
                }
                return (
                  <div> &nbsp; </div>
                );
              }}
            />
          </Collapse>
          <MenuItem onClick={this.handleThreatActorToggle.bind(this)} dense={true}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <Diamond/>
            </ListItemIcon>
            <ListItemText primary={t('Intrusion sets')} classes={{ root: classes.listText }}/>
            {this.state.threatActorOpen ? <ExpandLess/> : <ExpandMore/>}
          </MenuItem>
          <Collapse in={this.state.threatActorOpen} timeout='auto' unmountOnExit={true}>
            <QueryRenderer
              query={victimologyRightBarIntrusionSetsQuery}
              render={({ props }) => {
                if (props && props.intrusionSets) {
                  return (
                    <MenuList component='div' disablePadding={true}>
                      {props.intrusionSets.edges.map((intrusionSetEdge) => {
                        const intrusionSet = intrusionSetEdge.node;
                        return (
                          <MenuItem
                            key={intrusionSet.id}
                            className={classes.nested}
                            dense={true}
                          >
                            <Checkbox
                              tabIndex={-1}
                              disableRipple
                            />
                            <ListItemText primary={intrusionSet.name}/>
                          </MenuItem>
                        );
                      })}
                    </MenuList>
                  );
                }
                return (
                  <div> &nbsp; </div>
                );
              }}
            />
          </Collapse>
        </MenuList>
        <MenuList component='nav' classes={{ root: classes.menuList }} subheader={<ListSubheader classes={{ root: classes.subheader }} color='primary'>{t('Targeted entities types')}</ListSubheader>}>
          <MenuItem onClick={this.handleThreatActorToggle.bind(this)} dense={true}>
            <ListItemIcon classes={{ root: classes.listIcon }}>
              <Public/>
            </ListItemIcon>
            <ListItemText primary={t('Threat actors')} classes={{ root: classes.listText }}/>
            {this.state.threatActorOpen ? <ExpandLess/> : <ExpandMore/>}
          </MenuItem>
          <Collapse in={this.state.threatActorOpen} timeout='auto' unmountOnExit={true}>
            <MenuList component='div' disablePadding={true}>
              <MenuItem
                className={classes.nested}
                dense={true}
              >
                <ListItemText inset primary='test'/>
              </MenuItem>
            </MenuList>
          </Collapse>
        </MenuList>
      </Drawer>
    );
  }
}

VictimologyRightBar.propTypes = {
  attackPatternId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(VictimologyRightBar);
