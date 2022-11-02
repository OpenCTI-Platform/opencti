import React, { FunctionComponent, useContext, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { AccountBalanceOutlined, ShareOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import type { FormikHelpers } from 'formik/dist/types';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import ObjectOrganizationField from '../form/ObjectOrganizationField';
import { StixCoreHeaderSharedQuery } from './__generated__/StixCoreHeaderSharedQuery.graphql';
import { commitMutation } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { granted, KNOWLEDGE_KNUPDATE_KNORGARESTRICT, UserContext } from '../../../../utils/Security';

// region types
interface ContainerHeaderSharedProps {
  elementId: string
}

interface OrganizationForm {
  objectOrganization: { value: string, label: string }
}
// endregion

const useStyles = makeStyles(() => ({
  organizations: {
    marginRight: 7,
    float: 'left',
  },
  organization: {
    marginRight: 7,
    float: 'left',
  },
}));

const containerHeaderSharedQuery = graphql`
  query StixCoreHeaderSharedQuery($id: String!) {
    stixCoreObject(id: $id) {
      objectOrganization {
        edges {
          node {
            id
            name
          }
        }
      }
    }
  }
`;

const containerHeaderSharedQueryGroupDeleteMutation = graphql`
  mutation StixCoreHeaderSharedGroupDeleteMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId) {
        id
        objectOrganization {
          edges {
            node {
              id
              name
            }
          }
        }
      }
    }
  }
`;

const containerHeaderSharedGroupAddMutation = graphql`
  mutation StixCoreHeaderSharedGroupAddMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId) {
        id
        objectOrganization {
          edges {
            node {
              id
              name
            }
          }
        }
      }
    }
  }
`;

const StixCoreHeaderShared: FunctionComponent<ContainerHeaderSharedProps> = ({ elementId }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { me } = useContext(UserContext);
  const [displaySharing, setDisplaySharing] = useState(false);
  const userIsOrganizationEditor = granted(me, [KNOWLEDGE_KNUPDATE_KNORGARESTRICT]);
  // If user not an organization organizer, return empty div
  if (!userIsOrganizationEditor) {
    return <div />;
  }
  const handleOpenSharing = () => setDisplaySharing(true);
  const handleCloseSharing = () => setDisplaySharing(false);
  const { stixCoreObject } = useLazyLoadQuery<StixCoreHeaderSharedQuery>(containerHeaderSharedQuery, { id: elementId });
  const removeOrganization = (organizationId: string) => {
    commitMutation({
      mutation: containerHeaderSharedQueryGroupDeleteMutation,
      variables: { id: elementId, organizationId },
      onCompleted: undefined,
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };
  const onSubmitOrganizations = (values: OrganizationForm, {
    setSubmitting,
    resetForm,
  }: FormikHelpers<OrganizationForm>) => {
    const { objectOrganization } = values;
    if (objectOrganization.value) {
      commitMutation({
        mutation: containerHeaderSharedGroupAddMutation,
        variables: { id: elementId, organizationId: objectOrganization.value },
        onCompleted: () => {
          setSubmitting(false);
          resetForm();
          setDisplaySharing(false);
        },
        updater: undefined,
        optimisticUpdater: undefined,
        optimisticResponse: undefined,
        onError: undefined,
        setSubmitting: undefined,
      });
    }
  };
  const edges = stixCoreObject?.objectOrganization?.edges ?? [];
  return (
    <div className={classes.organizations}>
      {edges.map((edge) => (
        <Chip
          key={edge.node.id}
          icon={<AccountBalanceOutlined />}
          classes={{ root: classes.organization }}
          color="warning"
          variant="outlined"
          label={edge.node.name}
          onDelete={() => removeOrganization(edge.node.id)}
        />
      ))}
      <ToggleButtonGroup size="small" color="secondary" exclusive={true}>
          <Tooltip title={t('Share with organizations')}>
            <ToggleButton onClick={handleOpenSharing} value="shared">
              <ShareOutlined fontSize="small" color="primary" />
              <Formik initialValues={{ objectOrganization: { value: '', label: '' } }} onSubmit={onSubmitOrganizations}
                      onReset={handleCloseSharing}>
                {({ submitForm, handleReset, isSubmitting }) => (
                  <Dialog PaperProps={{ elevation: 1 }} open={displaySharing}
                          onClose={() => handleReset()} fullWidth={true}>
                    <DialogTitle>{t('Share with organizations')}</DialogTitle>
                    <DialogContent style={{ overflowY: 'hidden' }}>
                      <Form>
                        <ObjectOrganizationField name="objectOrganization"
                                                 style={{ width: '100%' }} label={t('Organizations')}
                                                 multiple={false} />
                      </Form>
                    </DialogContent>
                    <DialogActions>
                      <Button onClick={handleReset} disabled={isSubmitting}>
                        {t('Close')}
                      </Button>
                      <Button onClick={submitForm} disabled={isSubmitting} color="secondary">
                        {t('Share')}
                      </Button>
                    </DialogActions>
                  </Dialog>
                )}
              </Formik>
            </ToggleButton>
          </Tooltip>
      </ToggleButtonGroup>
    </div>
  );
};

export default StixCoreHeaderShared;
