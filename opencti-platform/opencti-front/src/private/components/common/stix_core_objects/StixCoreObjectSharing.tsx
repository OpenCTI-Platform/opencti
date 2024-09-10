import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { AccountBalanceOutlined } from '@mui/icons-material';
import { BankPlus } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import type { FormikHelpers } from 'formik/dist/types';
import ToggleButton from '@mui/material/ToggleButton';
import { Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import ObjectOrganizationField from '../form/ObjectOrganizationField';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { StixCoreObjectSharingQuery$data } from './__generated__/StixCoreObjectSharingQuery.graphql';
import useGranted, { KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import type { Theme } from '../../../../components/Theme';

// region types
interface ContainerHeaderSharedProps {
  elementId: string;
  variant: string;
  disabled?: boolean;
}

interface OrganizationForm {
  objectOrganization: { value: string; label: string };
}

// endregion

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  organizationInHeader: {
    margin: '4px 7px 0 0',
    float: 'left',
    fontSize: 12,
    lineHeight: '12px',
    height: 28,
    borderRadius: 4,
  },
  organization: {
    margin: '0 7px 0 0',
    float: 'left',
    fontSize: 12,
    lineHeight: '12px',
    height: 28,
    borderRadius: 4,
  },
}));

const containerHeaderSharedQuery = graphql`
  query StixCoreObjectSharingQuery($id: String!) {
    stixCoreObject(id: $id) {
      objectOrganization {
        id
        name
      }
    }
  }
`;

const containerHeaderSharedQueryGroupDeleteMutation = graphql`
  mutation StixCoreObjectSharingGroupDeleteMutation(
    $id: ID!
    $organizationId: ID!
  ) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId) {
        id
        objectOrganization {
          id
          name
        }
      }
    }
  }
`;

const containerHeaderSharedGroupAddMutation = graphql`
  mutation StixCoreObjectSharingGroupAddMutation(
    $id: ID!
    $organizationId: ID!
  ) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId) {
        id
        objectOrganization {
          id
          name
        }
      }
    }
  }
`;

const StixCoreObjectSharing: FunctionComponent<ContainerHeaderSharedProps> = ({
  elementId,
  variant,
  disabled = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [displaySharing, setDisplaySharing] = useState(false);
  const userIsOrganizationEditor = useGranted([KNOWLEDGE_KNUPDATE_KNORGARESTRICT]);
  const isEnterpriseEdition = useEnterpriseEdition();
  // If user not an organization organizer, return empty div
  if (!userIsOrganizationEditor) {
    return variant === 'header' ? (
      <div style={{ display: 'inline-block' }} />
    ) : (
      <div style={{ marginTop: -20 }} />
    );
  }
  const handleOpenSharing = () => setDisplaySharing(true);
  const handleCloseSharing = () => setDisplaySharing(false);
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
  const onSubmitOrganizations = (
    values: OrganizationForm,
    { setSubmitting, resetForm }: FormikHelpers<OrganizationForm>,
  ) => {
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
  const render = ({ stixCoreObject }: StixCoreObjectSharingQuery$data) => {
    const edges = stixCoreObject?.objectOrganization ?? [];
    if (variant === 'header') {
      return (
        <>
          {edges.map((edge) => (
            <Tooltip key={edge.id} title={edge.name}>
              <Chip
                icon={<AccountBalanceOutlined />}
                classes={{ root: classes.organizationInHeader }}
                color="primary"
                variant="outlined"
                label={truncate(edge.name, 15)}
                onDelete={() => removeOrganization(edge.id)}
                disabled={disabled}
              />
            </Tooltip>
          ))}
          <EETooltip title={t_i18n('Share with an organization')}>
            <ToggleButton
              value="shared"
              onClick={isEnterpriseEdition ? handleOpenSharing : () => {}}
              size="small"
              style={{ marginRight: 3 }}
              disabled={disabled}
            >
              <BankPlus
                fontSize="small"
                color={!disabled && isEnterpriseEdition ? 'primary' : 'disabled'}
              />
            </ToggleButton>
          </EETooltip>
          <Formik
            initialValues={{ objectOrganization: { value: '', label: '' } }}
            onSubmit={onSubmitOrganizations}
            onReset={handleCloseSharing}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={displaySharing}
                onClose={() => handleReset()}
                fullWidth={true}
              >
                <DialogTitle>{t_i18n('Share with an organization')}</DialogTitle>
                <DialogContent style={{ overflowY: 'hidden' }}>
                  <Form>
                    <ObjectOrganizationField
                      name="objectOrganization"
                      style={{ width: '100%' }}
                      label={t_i18n('Organization')}
                      multiple={false}
                    />
                  </Form>
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t_i18n('Close')}
                  </Button>
                  <Button
                    onClick={submitForm}
                    disabled={isSubmitting}
                    color="secondary"
                  >
                    {t_i18n('Share')}
                  </Button>
                </DialogActions>
              </Dialog>
            )}
          </Formik>
        </>
      );
    }
    return (
      <>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t_i18n('Organizations sharing')}
        </Typography>
        <EETooltip title={t_i18n('Share with an organization')}>
          <IconButton
            color="primary"
            aria-label="Label"
            onClick={isEnterpriseEdition ? handleOpenSharing : () => {}}
            style={{ float: 'left', margin: '-15px 0 0 -2px' }}
            size="large"
            disabled={disabled}
          >
            <BankPlus fontSize="small" color={!disabled && isEnterpriseEdition ? 'primary' : 'disabled'} />
          </IconButton>
        </EETooltip>
        <div className="clearfix" />
        {edges.map((edge) => (
          <Tooltip key={edge.id} title={edge.name}>
            <Chip
              icon={<AccountBalanceOutlined />}
              classes={{ root: classes.organization }}
              color="primary"
              variant="outlined"
              label={truncate(edge.name, 15)}
              onDelete={() => removeOrganization(edge.id)}
              disabled={disabled}
            />
          </Tooltip>
        ))}
        <div className="clearfix" />
        <Formik
          initialValues={{ objectOrganization: { value: '', label: '' } }}
          onSubmit={onSubmitOrganizations}
          onReset={handleCloseSharing}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={displaySharing}
              onClose={() => handleReset()}
              fullWidth={true}
            >
              <DialogTitle>{t_i18n('Share with an organization')}</DialogTitle>
              <DialogContent style={{ overflowY: 'hidden' }}>
                <Form>
                  <ObjectOrganizationField
                    name="objectOrganization"
                    style={{ width: '100%' }}
                    label={t_i18n('Organization')}
                    multiple={false}
                  />
                </Form>
              </DialogContent>
              <DialogActions>
                <Button onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Close')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                  color="secondary"
                >
                  {t_i18n('Share')}
                </Button>
              </DialogActions>
            </Dialog>
          )}
        </Formik>
      </>
    );
  };
  return (
    <QueryRenderer
      query={containerHeaderSharedQuery}
      variables={{ id: elementId }}
      render={(result: { props: StixCoreObjectSharingQuery$data }) => {
        if (result.props) {
          return render(result.props);
        }
        return <div />;
      }}
    />
  );
};

export default StixCoreObjectSharing;
