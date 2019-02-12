import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import {
  compose, map, pathOr, pipe, union,
} from 'ramda';
import { Formik, Field, Form } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import Drawer from '@material-ui/core/Drawer';
import Checkbox from '@material-ui/core/Checkbox';
import inject18n from '../../../components/i18n';
import Autocomplete from '../../../components/Autocomplete';
import { fetchQuery } from '../../../relay/environment';

const targetingTypes = [
  'All',
  'Campaign',
  'Incident',
];

const targetTypes = [
  'All',
  'Country',
  'Sector',
  'Organization',
];

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '20px 10px 20px 10px',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  toolbar: theme.mixins.toolbar,
});

const victimologyRightBarThreatActorsSearchQuery = graphql`
    query VictimologyRightBarThreatActorsQuery($search: String) {
        threatActors(search: $search) {
            edges {
                node {
                    id
                    name
                    type
                }
            }
        }
    }
`;

const victimologyRightBarIntrusionSetsSearchQuery = graphql`
    query VictimologyRightBarIntrusionSetsQuery($search: String) {
        intrusionSets(search: $search) {
            edges {
                node {
                    id
                    name
                    type
                }
            }
        }
    }
`;

class VictimologyRightBar extends Component {
  constructor(props) {
    super(props);
    this.state = { threats: [] };
  }

  searchThreats(event) {
    fetchQuery(victimologyRightBarThreatActorsSearchQuery, {
      search: event.target.value,
      first: 10,
    }).then((data) => {
      const threatActors = pipe(
        pathOr([], ['threatActors', 'edges']),
        map(n => ({ label: n.node.name, value: n.node.id, type: n.node.type })),
      )(data);
      this.setState({ threats: union(this.state.threats, threatActors) });
    });
    fetchQuery(victimologyRightBarIntrusionSetsSearchQuery, {
      search: event.target.value,
      first: 10,
    }).then((data) => {
      const intrusionSets = pipe(
        pathOr([], ['intrusionSets', 'edges']),
        map(n => ({ label: n.node.name, value: n.node.id, type: n.node.type })),
      )(data);
      this.setState({ threats: union(this.state.threats, intrusionSets) });
    });
  }

  render() {
    const {
      t,
      classes,
      handleSelectThreat,
      handleSelectTargetingType,
      selectedTargetingTypes,
      handleSelectTargetType,
      selectedTargetTypes,
    } = this.props;
    return (
      <Drawer variant='permanent' anchor='right' classes={{ paper: classes.drawerPaper }}>
        <div className={classes.toolbar}/>
        <Typography variant='h3' gutterBottom={true}>
          {t('Origins of the targeting')}
        </Typography>
        <Formik
          enableReinitialize={true}
          initialValues={{ searchThreat: '' }}
          render={() => (
            <Form style={{ marginTop: -30 }}>
              <Field
                name='searchThreat'
                component={Autocomplete}
                labelDisplay={false}
                multiple={false}
                label={t('Search for a threat...')}
                options={this.state.threats}
                onInputChange={this.searchThreats.bind(this)}
                onChange={handleSelectThreat.bind(this)}
              />
            </Form>
          )}
        />
        <Typography variant='h3' gutterBottom={true} style={{ marginTop: 20 }}>
          {t('Types of the targeting')}
        </Typography>
        <List className={classes.root}>
          {targetingTypes.map((targetingType) => {
            const selected = (targetingType === 'All' && selectedTargetingTypes === null)
              || (selectedTargetingTypes !== null && selectedTargetingTypes.indexOf(targetingType) !== -1);
            return (
              <ListItem
                key={targetingType}
                dense={true}
                button={true}
                style={{ padding: 0 }}
                onClick={handleSelectTargetingType.bind(this, targetingType)}
              >
                <Checkbox
                  checked={selected}
                  disableRipple={true}
                />
                <ListItemText primary={t(targetingType)}/>
              </ListItem>
            );
          })}
        </List>
        <Typography variant='h3' gutterBottom={true} style={{ marginTop: 10 }}>
          {t('Types of the targets')}
        </Typography>
        <List className={classes.root}>
          {targetTypes.map((targetType) => {
            const selected = (targetType === 'All' && selectedTargetTypes === null)
              || (selectedTargetTypes !== null && selectedTargetTypes.indexOf(targetType) !== -1);
            return (
              <ListItem
                key={targetType}
                dense={true}
                button={true}
                style={{ padding: 0 }}
                onClick={handleSelectTargetType.bind(this, targetType)}
              >
                <Checkbox
                  checked={selected}
                  disableRipple={true}
                />
                <ListItemText primary={t(targetType)}/>
              </ListItem>
            );
          })}
        </List>
      </Drawer>
    );
  }
}

VictimologyRightBar.propTypes = {
  attackPatternId: PropTypes.string,
  handleSelectThreat: PropTypes.func,
  handleSelectTargetingType: PropTypes.func,
  selectedTargetingTypes: PropTypes.array,
  handleSelectTargetType: PropTypes.func,
  selectedTargetTypes: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(VictimologyRightBar);
