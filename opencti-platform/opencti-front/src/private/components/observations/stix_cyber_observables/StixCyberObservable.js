import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import StixCyberObservableHeader from './StixCyberObservableHeader';
import StixCyberObservableOverview from './StixCyberObservableOverview';
import StixCyberObservableDetails from './StixCyberObservableDetails';
import StixCyberObservableEdition from './StixCyberObservableEdition';
import EntityLastReports from '../../analysis/reports/StixCoreObjectLastReports';
import StixCyberObservableIndicators from './StixCyberObservableIndicators';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectNotes from '../../analysis/notes/StixCoreObjectNotes';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class StixCyberObservableComponent extends Component {
  render() {
    const { classes, stixCyberObservable } = this.props;
    return (
      <div className={classes.container}>
        <StixCyberObservableHeader stixCyberObservable={stixCyberObservable} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={2}>
            <StixCyberObservableOverview
              stixCyberObservable={stixCyberObservable}
            />
          </Grid>
          <Grid item={true} xs={5}>
            <StixCyberObservableDetails
              stixCyberObservable={stixCyberObservable}
            />
          </Grid>
          <Grid item={true} xs={5}>
            <EntityLastReports stixCyberObservableId={stixCyberObservable.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 30 }}
        >
          <Grid item={true} xs={7}>
            <StixCyberObservableIndicators
              stixCyberObservable={stixCyberObservable}
            />
          </Grid>
          <Grid item={true} xs={5}>
            <StixCoreObjectExternalReferences stixCoreObjectId={stixCyberObservable.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes
          entityId={stixCyberObservable.id}
          inputType="observableRefs"
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCyberObservableEdition
            stixCyberObservableId={stixCyberObservable.id}
          />
        </Security>
      </div>
    );
  }
}

StixCyberObservableComponent.propTypes = {
  stixCyberObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const StixCyberObservable = createFragmentContainer(
  StixCyberObservableComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservable_stixCyberObservable on StixCyberObservable {
        id
        ...StixCyberObservableHeader_stixCyberObservable
        ...StixCyberObservableOverview_stixCyberObservable
        ...StixCyberObservableDetails_stixCyberObservable
        ...StixCyberObservableIndicators_stixCyberObservable
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(StixCyberObservable);
