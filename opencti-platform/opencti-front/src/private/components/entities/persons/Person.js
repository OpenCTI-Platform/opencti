import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, dissoc, isNil, propOr,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import PersonOverview from './PersonOverview';
import PersonDetails from './PersonDetails';
import PersonEdition from './PersonEdition';
import PersonPopover from './PersonPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityCampaignsChart from '../../threats/campaigns/EntityCampaignsChart';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityIncidentsChart from '../../threats/incidents/EntityIncidentsChart';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixObjectNotes from '../../common/stix_object/StixObjectNotes';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class PersonComponent extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-person-${props.person.id}`,
    );
    this.state = {
      viewAs: propOr('knowledge', 'viewAs', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-person-${this.props.person.id}`,
      dissoc('filters', this.state),
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const { classes, person } = this.props;
    const { viewAs } = this.state;
    if (viewAs === 'author') {
      return (
        <div className={classes.container}>
          <StixDomainEntityHeader
            stixDomainEntity={person}
            PopoverComponent={<PersonPopover />}
            onViewAs={this.handleChangeViewAs.bind(this)}
            viewAs={this.state.viewAs}
            disablePopover={!isNil(person.external)}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={3}>
              <PersonOverview person={person} />
            </Grid>
            <Grid item={true} xs={3}>
              <PersonDetails person={person} />
            </Grid>
            <Grid item={true} xs={6}>
              <EntityLastReports authorId={person.id} />
            </Grid>
          </Grid>
          <StixObjectNotes entityId={person.id} />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
            style={{ marginTop: 15 }}
          >
            <Grid item={true} xs={12}>
              <EntityReportsChart authorId={person.id} />
            </Grid>
          </Grid>
          {isNil(person.external) ? (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <PersonEdition personId={person.id} />
            </Security>
          ) : (
            ''
          )}
        </div>
      );
    }
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={person}
          PopoverComponent={<PersonPopover />}
          onViewAs={this.handleChangeViewAs.bind(this)}
          viewAs={this.state.viewAs}
          disablePopover={!isNil(person.external)}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <PersonOverview person={person} />
          </Grid>
          <Grid item={true} xs={3}>
            <PersonDetails person={person} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={person.id} />
          </Grid>
        </Grid>
        <StixObjectNotes entityId={person.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart entityId={person.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityIncidentsChart entityId={person.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={person.id} />
          </Grid>
        </Grid>
        {isNil(person.external) ? (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <PersonEdition personId={person.id} />
          </Security>
        ) : (
          ''
        )}
      </div>
    );
  }
}

PersonComponent.propTypes = {
  person: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Person = createFragmentContainer(PersonComponent, {
  person: graphql`
    fragment Person_person on User {
      id
      name
      alias
      external
      ...PersonOverview_person
      ...PersonDetails_person
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Person);
