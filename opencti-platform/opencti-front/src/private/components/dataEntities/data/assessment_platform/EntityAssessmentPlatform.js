/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Redirect } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../../components/i18n';
import EntityAssessmentPlatformDetails from './EntityAssessmentPlatformDetails';
import EntitiesAssessmentPlatformsPopover from './EntitiesAssessmentPlatformsPopover';
import EntitiesAssessmentPlatformsDeletion from './EntitiesAssessmentPlatformsDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import AssessmentPlatformEntityEditionContainer from './AssessmentPlatformEntityEditionContainer';
import EntitiesAssessmentPlatformsCreation from './EntitiesAssessmentPlatformsCreation';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class EntityAssessmentPlatformComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayEdit: false,
      openDataCreation: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleOpenNewCreation() {
    this.setState({ openDataCreation: !this.state.openDataCreation });
  }

  render() {
    const {
      classes,
      assessmentPlatform,
      history,
      refreshQuery,
      location,
    } = this.props;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            history={history}
            name={assessmentPlatform.name}
            cyioDomainObject={assessmentPlatform}
            goBack='/data/entities/assessment_platform'
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            PopoverComponent={<EntitiesAssessmentPlatformsPopover />}
            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
            OperationsComponent={<EntitiesAssessmentPlatformsDeletion />}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <EntityAssessmentPlatformDetails assessmentPlatform={assessmentPlatform} history={history} refreshQuery={refreshQuery} />
            </Grid>
          </Grid>
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
            style={{ marginTop: 25 }}
          >
            <Grid item={true} xs={6}>
              <CyioCoreObjectExternalReferences
                typename={assessmentPlatform.__typename}
                externalReferences={assessmentPlatform.links}
                fieldName='links'
                cyioCoreObjectId={assessmentPlatform?.id}
                refreshQuery={refreshQuery}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={assessmentPlatform.__typename}
                notes={assessmentPlatform.remarks}
                refreshQuery={refreshQuery}
                fieldName='remarks'
                marginTop='0px'
                cyioCoreObjectOrCyioCoreRelationshipId={assessmentPlatform?.id}
              />
            </Grid>
          </Grid>
        </div>
        <EntitiesAssessmentPlatformsCreation
          openDataCreation={this.state.openDataCreation}
          handleAssessPlatformCreation={this.handleOpenNewCreation.bind(this)}
          history={history}
        />
        <AssessmentPlatformEntityEditionContainer
          displayEdit={this.state.displayEdit}
          assessmentPlatform={assessmentPlatform}
          history={history}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </>
    );
  }
}

EntityAssessmentPlatformComponent.propTypes = {
  assessmentPlatform: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const EntityAssessmentPlatform = createFragmentContainer(EntityAssessmentPlatformComponent, {
  assessmentPlatform: graphql`
    fragment EntityAssessmentPlatform_assessmentPlatform on AssessmentPlatform {
      __typename
      id
      created
      modified
      name
      description
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
      links {
        __typename
        id
        source_name
        description
        entity_type
        url
        hashes {
          value
        }
        external_id
      }
      remarks {
        __typename
        id
        entity_type
        abstract
        content
        authors
      }
      ...EntityAssessmentPlatformDetails_assessmentPlatform
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityAssessmentPlatform);
