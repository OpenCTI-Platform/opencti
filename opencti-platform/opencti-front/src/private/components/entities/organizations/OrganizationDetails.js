import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Chip from '@material-ui/core/Chip';
import Markdown from 'react-markdown';
import StixDomainObjectLabels from '../../common/stix_domain_objects/StixDomainObjectLabels';
import inject18n from '../../../../components/i18n';
import ItemReliability from '../../../../components/ItemReliability';
import ItemCreator from '../../../../components/ItemCreator';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  chip: {
    fontSize: 12,
    height: 25,
    margin: '0 7px 7px 0',
    backgroundColor: '#795548',
  },
});

class OrganizationDetailsComponent extends Component {
  render() {
    const { t, classes, organization } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <StixDomainObjectLabels
            labels={organization.labels}
            id={organization.id}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator creator={organization.creator} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Organization type')}
          </Typography>
          <Chip
            classes={{ root: classes.chip }}
            label={t(
              organization.x_opencti_organization_type
                ? `organization_${organization.x_opencti_organization_type}`
                : 'organization_other',
            )}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Reliability')}
          </Typography>
          <ItemReliability
            reliability={organization.reliability}
            label={t(`reliability_${organization.reliability}`)}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Contact information')}
          </Typography>
          <Markdown
            className="markdown"
            source={organization.contact_information}
          />
        </Paper>
      </div>
    );
  }
}

OrganizationDetailsComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const OrganizationDetails = createFragmentContainer(
  OrganizationDetailsComponent,
  {
    organization: graphql`
      fragment OrganizationDetails_organization on Organization {
        id
        reliability
        x_opencti_organization_type
        contact_information
        creator {
          id
          name
        }
        labels {
          edges {
            node {
              id
              value
              color
            }

          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(OrganizationDetails);
