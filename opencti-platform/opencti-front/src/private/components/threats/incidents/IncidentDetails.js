import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Markdown from 'react-markdown';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixDomainEntityTags from '../../common/stix_domain_entities/StixDomainEntityTags';
import ItemCreator from '../../../../components/ItemCreator';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class IncidentDetailsComponent extends Component {
  render() {
    const {
      fld, t, classes, incident,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <StixDomainEntityTags tags={incident.tags} id={incident.id} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator creator={incident.creator} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('First seen')}
          </Typography>
          {fld(incident.first_seen)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Last seen')}
          </Typography>
          {fld(incident.last_seen)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Objective')}
          </Typography>
          <Markdown className="markdown" source={incident.objective} />
        </Paper>
      </div>
    );
  }
}

IncidentDetailsComponent.propTypes = {
  incident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IncidentDetails = createFragmentContainer(IncidentDetailsComponent, {
  incident: graphql`
    fragment IncidentDetails_incident on Incident {
      id
      first_seen
      last_seen
      objective
      creator {
          id
          name
        }
      tags {
        edges {
          node {
            id
            tag_type
            value
            color
          }
          relation {
            id
          }
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(IncidentDetails);
