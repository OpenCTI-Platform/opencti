import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as R from 'ramda';
import { Form, Formik } from 'formik';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import IncidentEditionOverview from './IncidentEditionOverview';
import IncidentEditionDetails from './IncidentEditionDetails';
import { commitMutation } from '../../../../relay/environment';
import { convertOrganizations } from '../../../../utils/Edition';
import Security, { KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from '../../../../utils/Security';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';

const styles = (theme) => ({
  restrictions: {
    padding: 10,
    backgroundColor: theme.palette.background.nav,
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
});

const incidentMutationGroupAdd = graphql`
  mutation IncidentEditionContainerGroupAddMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId) {
        ...IncidentEditionOverview_incident
      }
    }
  }
`;

const incidentMutationGroupDelete = graphql`
  mutation IncidentEditionContainerGroupDeleteMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId) {
        ...IncidentEditionOverview_incident
      }
    }
  }
`;

class IncidentEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { currentTab: 0 };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  handleChangeObjectOrganization(name, values) {
    const { incident } = this.props;
    const currentValues = R.pipe(
      R.pathOr([], ['objectOrganization', 'edges']),
      R.map((n) => ({
        label: n.node.name,
        value: n.node.id,
      })),
    )(incident);
    const added = R.difference(values, currentValues);
    const removed = R.difference(currentValues, values);
    if (added.length > 0) {
      commitMutation({
        mutation: incidentMutationGroupAdd,
        variables: {
          id: this.props.incident.id,
          organizationId: R.head(added).value,
        },
      });
    }
    if (removed.length > 0) {
      commitMutation({
        mutation: incidentMutationGroupDelete,
        variables: {
          id: this.props.incident.id,
          organizationId: R.head(removed).value,
        },
      });
    }
  }

  render() {
    const { t, classes, handleClose, incident } = this.props;
    const { editContext } = incident;
    const objectOrganization = convertOrganizations(incident);
    const initialValues = R.pipe(
      R.assoc('objectOrganization', objectOrganization),
      R.pick(['objectOrganization']),
    )(incident);
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update an incident')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}>
            <Formik enableReinitialize={true} initialValues={initialValues}>
              {() => (
                  <Form>
                    <div className={classes.restrictions}>
                      <ObjectOrganizationField name="objectOrganization" style={{ width: '100%' }}
                                        onChange={this.handleChangeObjectOrganization.bind(this)}/>
                    </div>
                  </Form>)}
            </Formik>
          </Security>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={this.state.currentTab}
              onChange={this.handleChangeTab.bind(this)}
            >
              <Tab label={t('Overview')} />
              <Tab label={t('Details')} />
            </Tabs>
          </Box>
          {this.state.currentTab === 0 && (
            <IncidentEditionOverview
              incident={incident}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )}
          {this.state.currentTab === 1 && (
            <IncidentEditionDetails
              incident={incident}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )}
        </div>
      </div>
    );
  }
}

IncidentEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  incident: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const IncidentEditionContainerFragment = createFragmentContainer(
  IncidentEditionContainer,
  {
    incident: graphql`
      fragment IncidentEditionContainer_incident on Incident {
        id
        ...IncidentEditionOverview_incident
        ...IncidentEditionDetails_incident
        objectOrganization {
          edges {
            node {
              id
              name
            }
          }
        }
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IncidentEditionContainerFragment);
