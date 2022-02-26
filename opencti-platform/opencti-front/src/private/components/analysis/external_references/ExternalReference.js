import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExternalReferenceOverview from './ExternalReferenceOverview';
import ExternalReferenceDetails from './ExternalReferenceDetails';
import ExternalReferenceEdition from './ExternalReferenceEdition';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import ExternalReferencePopover from './ExternalReferencePopover';
import ExternalReferenceHeader from './ExternalReferenceHeader';
import ExternalReferenceFileImportViewer from './ExternalReferenceFileImportViewer';
import ExternalReferenceStixCoreObjects from './ExternalReferenceStixCoreObjects';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class ExternalReferenceComponent extends Component {
  render() {
    const { classes, externalReference, connectorsImport } = this.props;
    return (
      <div className={classes.container}>
        <ExternalReferenceHeader
          externalReference={externalReference}
          PopoverComponent={<ExternalReferencePopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <ExternalReferenceOverview externalReference={externalReference} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <ExternalReferenceDetails externalReference={externalReference} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <ExternalReferenceStixCoreObjects
              externalReference={externalReference}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <ExternalReferenceFileImportViewer
              externalReference={externalReference}
              connectorsImport={connectorsImport}
            />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ExternalReferenceEdition
            externalReferenceId={externalReference.id}
          />
        </Security>
      </div>
    );
  }
}

ExternalReferenceComponent.propTypes = {
  externalReference: PropTypes.object,
  connectorsImport: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ExternalReference = createFragmentContainer(ExternalReferenceComponent, {
  externalReference: graphql`
    fragment ExternalReference_externalReference on ExternalReference {
      id
      ...ExternalReferenceHeader_externalReference
      ...ExternalReferenceOverview_externalReference
      ...ExternalReferenceDetails_externalReference
      ...ExternalReferenceFileImportViewer_entity
      ...ExternalReferenceStixCoreObjects_externalReference
    }
  `,
  connectorsImport: graphql`
    fragment ExternalReference_connectorsImport on Connector
    @relay(plural: true) {
      ...ExternalReferenceFileImportViewer_connectorsImport
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ExternalReference);
