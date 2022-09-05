import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import { Form, Formik } from 'formik';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import StixCyberObservableEditionOverview from './StixCyberObservableEditionOverview';
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
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

const stixCyberObservableMutationGroupAdd = graphql`
  mutation StixCyberObservableEditionContainerGroupAddMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId) {
        ...StixCyberObservableEditionOverview_stixCyberObservable
      }
    }
  }
`;

const stixCyberObservableMutationGroupDelete = graphql`
  mutation StixCyberObservableEditionContainerGroupDeleteMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId) {
        ...StixCyberObservableEditionOverview_stixCyberObservable
      }
    }
  }
`;

class StixCyberObservableEditionContainer extends Component {
  handleChangeObjectOrganization(name, values) {
    const { stixCyberObservable } = this.props;
    const currentValues = R.pipe(
      R.pathOr([], ['objectOrganization', 'edges']),
      R.map((n) => ({
        label: n.node.name,
        value: n.node.id,
      })),
    )(stixCyberObservable);
    const added = R.difference(values, currentValues);
    const removed = R.difference(currentValues, values);
    if (added.length > 0) {
      commitMutation({
        mutation: stixCyberObservableMutationGroupAdd,
        variables: {
          id: this.props.stixCyberObservable.id,
          organizationId: R.head(added).value,
        },
      });
    }
    if (removed.length > 0) {
      commitMutation({
        mutation: stixCyberObservableMutationGroupDelete,
        variables: {
          id: this.props.stixCyberObservable.id,
          organizationId: R.head(removed).value,
        },
      });
    }
  }

  render() {
    const { t, classes, handleClose, stixCyberObservable } = this.props;
    const { editContext } = stixCyberObservable;
    const objectOrganization = convertOrganizations(stixCyberObservable);
    const initialValues = R.pipe(
      R.assoc('objectOrganization', objectOrganization),
      R.pick(['objectOrganization']),
    )(stixCyberObservable);
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
            {t('Update an observable')}
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
          <StixCyberObservableEditionOverview
            stixCyberObservable={this.props.stixCyberObservable}
            enableReferences={this.props.enableReferences}
            context={editContext}
            handleClose={handleClose.bind(this)}
          />
        </div>
      </div>
    );
  }
}

StixCyberObservableEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  stixCyberObservable: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StixCyberObservableEditionFragment = createFragmentContainer(
  StixCyberObservableEditionContainer,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableEditionContainer_stixCyberObservable on StixCyberObservable {
        id
        ...StixCyberObservableEditionOverview_stixCyberObservable
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
)(StixCyberObservableEditionFragment);
