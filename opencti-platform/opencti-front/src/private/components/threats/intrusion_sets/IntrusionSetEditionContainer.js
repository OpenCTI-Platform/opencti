import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import { Form, Formik } from 'formik';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import IntrusionSetEditionOverview from './IntrusionSetEditionOverview';
import IntrusionSetEditionDetails from './IntrusionSetEditionDetails';
import Security, { KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from '../../../../utils/Security';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import { convertOrganizations } from '../../../../utils/Edition';
import { commitMutation } from '../../../../relay/environment';

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

const intrusionSetMutationGroupAdd = graphql`
  mutation IntrusionSetEditionContainerGroupAddMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId) {
        ...IntrusionSetEditionOverview_intrusionSet
      }
    }
  }
`;

const intrusionSetMutationGroupDelete = graphql`
  mutation IntrusionSetEditionContainerGroupDeleteMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId) {
        ...IntrusionSetEditionOverview_intrusionSet
      }
    }
  }
`;

class IntrusionSetEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { currentTab: 0 };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  handleChangeObjectOrganization(name, values) {
    const { intrusionSet } = this.props;
    const currentValues = R.pipe(
      R.pathOr([], ['objectOrganization', 'edges']),
      R.map((n) => ({
        label: n.node.name,
        value: n.node.id,
      })),
    )(intrusionSet);
    const added = R.difference(values, currentValues);
    const removed = R.difference(currentValues, values);
    if (added.length > 0) {
      commitMutation({
        mutation: intrusionSetMutationGroupAdd,
        variables: {
          id: this.props.intrusionSet.id,
          organizationId: R.head(added).value,
        },
      });
    }
    if (removed.length > 0) {
      commitMutation({
        mutation: intrusionSetMutationGroupDelete,
        variables: {
          id: this.props.intrusionSet.id,
          organizationId: R.head(removed).value,
        },
      });
    }
  }

  render() {
    const { t, classes, handleClose, intrusionSet } = this.props;
    const { editContext } = intrusionSet;
    const objectOrganization = convertOrganizations(intrusionSet);
    const initialValues = R.pipe(
      R.assoc('objectOrganization', objectOrganization),
      R.pick(['objectOrganization']),
    )(intrusionSet);
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
            {t('Update an intrusion set')}
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
            <IntrusionSetEditionOverview
              intrusionSet={intrusionSet}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )}
          {this.state.currentTab === 1 && (
            <IntrusionSetEditionDetails
              intrusionSet={intrusionSet}
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

IntrusionSetEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  intrusionSet: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const IntrusionSetEditionFragment = createFragmentContainer(
  IntrusionSetEditionContainer,
  {
    intrusionSet: graphql`
      fragment IntrusionSetEditionContainer_intrusionSet on IntrusionSet {
        id
        ...IntrusionSetEditionOverview_intrusionSet
        ...IntrusionSetEditionDetails_intrusionSet
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
)(IntrusionSetEditionFragment);
