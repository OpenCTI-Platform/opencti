import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Markdown from 'react-markdown';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemCreator from '../../../../components/ItemCreator';

const styles = () => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class OrganizationOverviewComponent extends Component {
  render() {
    const {
      t, fld, classes, organization,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Organization type')}
          </Typography>
          {t(
            organization.organization_class
              ? `organization_${organization.organization_class}`
              : 'organization_other',
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creation date')}
          </Typography>
          {fld(organization.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fld(organization.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator
            createdByRef={pathOr(null, ['createdByRef', 'node'], organization)}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <Markdown className="markdown" source={organization.description} />
        </Paper>
      </div>
    );
  }
}

OrganizationOverviewComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const OrganizationOverview = createFragmentContainer(
  OrganizationOverviewComponent,
  {
    organization: graphql`
      fragment OrganizationOverview_organization on Organization {
        id
        organization_class
        name
        description
        created
        modified
        createdByRef {
          node {
            name
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(OrganizationOverview);
