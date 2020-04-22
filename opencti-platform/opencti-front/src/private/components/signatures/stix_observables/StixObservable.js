import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import StixObservableHeader from './StixObservableHeader';
import StixObservableOverview from './StixObservableOverview';
import StixObservableDetails from './StixObservableDetails';
import StixObservableEdition from './StixObservableEdition';
import EntityLastReports from '../../reports/EntityLastReports';
import StixObservableIndicators from './StixObservableIndicators';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import EntityExternalReferences from '../../common/external_references/EntityExternalReferences';
import StixObjectNotes from '../../common/stix_object/StixObjectNotes';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class StixObservableComponent extends Component {
  render() {
    const { classes, stixObservable } = this.props;
    return (
      <div className={classes.container}>
        <StixObservableHeader stixObservable={stixObservable} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <StixObservableOverview stixObservable={stixObservable} />
          </Grid>
          <Grid item={true} xs={3}>
            <StixObservableDetails stixObservable={stixObservable} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports stixObservableId={stixObservable.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 30 }}
        >
          <Grid item={true} xs={8}>
            <StixObservableIndicators stixObservable={stixObservable} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityExternalReferences entityId={stixObservable.id} />
          </Grid>
        </Grid>
        <StixObjectNotes
          entityId={stixObservable.id}
          inputType="observableRefs"
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixObservableEdition stixObservableId={stixObservable.id} />
        </Security>
      </div>
    );
  }
}

StixObservableComponent.propTypes = {
  stixObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const StixObservable = createFragmentContainer(StixObservableComponent, {
  stixObservable: graphql`
    fragment StixObservable_stixObservable on StixObservable {
      id
      ...StixObservableHeader_stixObservable
      ...StixObservableOverview_stixObservable
      ...StixObservableDetails_stixObservable
      ...StixObservableIndicators_stixObservable
    }
  `,
});

export default compose(inject18n, withStyles(styles))(StixObservable);
