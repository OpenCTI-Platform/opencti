import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ContainerHeader from '../../common/containers/ContainerHeader';
import OpinionDetails from './OpinionDetails';
import OpinionEdition from './OpinionEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import OpinionPopover from './OpinionPopover';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class OpinionComponent extends Component {
  render() {
    const { classes, opinion } = this.props;
    return (
      <div className={classes.container}>
        <ContainerHeader
          container={opinion}
          PopoverComponent={<OpinionPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={opinion} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <ContainerStixObjectsOrStixRelationships container={opinion} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={12}>
            <OpinionDetails opinion={opinion} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <StixCoreObjectExternalReferences stixCoreObjectId={opinion.id} />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory stixCoreObjectId={opinion.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <OpinionEdition opinionId={opinion.id} />
        </Security>
      </div>
    );
  }
}

OpinionComponent.propTypes = {
  opinion: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Opinion = createFragmentContainer(OpinionComponent, {
  opinion: graphql`
    fragment Opinion_opinion on Opinion {
      id
      standard_id
      x_opencti_stix_ids
      spec_version
      revoked
      confidence
      created
      modified
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      creator {
        id
        name
      }
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
      ...OpinionDetails_opinion
      ...ContainerHeader_container
      ...ContainerStixObjectsOrStixRelationships_container
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Opinion);
