import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import SystemDetails from './SystemDetails';
import SystemEdition from './SystemEdition';
import SystemPopover from './SystemPopover';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class SystemComponent extends Component {
  render() {
    const { classes, system, viewAs, onViewAs } = this.props;
    const lastReportsProps = viewAs === 'knowledge'
      ? { stixCoreObjectOrStixCoreRelationshipId: system.id }
      : { authorId: system.id };
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={system}
          isOpenctiAlias={true}
          PopoverComponent={<SystemPopover />}
          onViewAs={onViewAs.bind(this)}
          viewAs={viewAs}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={system} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <SystemDetails system={system} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          {viewAs === 'knowledge' && (
            <Grid item={true} xs={6}>
              <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                stixObjectOrStixRelationshipId={system.id}
                stixObjectOrStixRelationshipLink={`/dashboard/entities/systems/${system.id}/knowledge`}
              />
            </Grid>
          )}
          <Grid item={true} xs={viewAs === 'knowledge' ? 6 : 12}>
            <StixCoreObjectOrStixCoreRelationshipLastReports
              {...lastReportsProps}
            />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <StixCoreObjectExternalReferences stixCoreObjectId={system.id} />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory stixCoreObjectId={system.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={system.id}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <SystemEdition systemId={system.id} />
        </Security>
      </div>
    );
  }
}

SystemComponent.propTypes = {
  system: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
};

const System = createFragmentContainer(SystemComponent, {
  system: graphql`
    fragment System_system on System {
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
      objectMarking {
        edges {
          node {
            id
            definition
            x_opencti_color
          }
        }
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
      name
      x_opencti_aliases
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
      ...SystemDetails_system
    }
  `,
});

export default compose(inject18n, withStyles(styles))(System);
