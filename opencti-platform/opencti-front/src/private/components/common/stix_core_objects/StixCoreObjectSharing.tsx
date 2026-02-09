import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import { AccountBalanceOutlined } from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import DialogActions from '@mui/material/DialogActions';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Form, Formik } from 'formik';
import type { FormikHelpers } from 'formik/dist/types';
import { BankPlus } from 'mdi-material-ui';
import { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from '../../../../utils/hooks/useGranted';
import { truncate } from '../../../../utils/String';
import ObjectOrganizationField from '../form/ObjectOrganizationField';
import { StixCoreObjectSharingQuery$data } from './__generated__/StixCoreObjectSharingQuery.graphql';

// region types
interface ContainerHeaderSharedProps {
  elementId: string;
  variant: string;
  disabled?: boolean;
  handleClose: () => void;
  open?: boolean;
  inContainer?: boolean;
}

interface OrganizationForm {
  objectOrganization: { value: string; label: string };
}

// endregion

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
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
    $organizationId: [ID!]!
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
    $organizationId: [ID!]!
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
  open,
  handleClose,
  inContainer = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const [displaySharing, setDisplaySharing] = useState(false);
  const userIsOrganizationEditor = useGranted([KNOWLEDGE_KNUPDATE_KNORGARESTRICT]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const notifySuccessMessage = (
    <span>
      {t_i18n(
        'The background task has been executed. You can monitor it on',
      )}{' '}
      <Link to="/dashboard/data/processing/tasks">{t_i18n('the dedicated page')}</Link>
      .
    </span>
  );
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
          if (inContainer) {
            MESSAGING$.notifySuccess(notifySuccessMessage);
          }
          resetForm();
          handleClose?.();
          handleCloseSharing();
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
          {!handleClose && (
            <EETooltip title={t_i18n('Share with an organization')}>
              <ToggleButton
                value="shared"
                onClick={isEnterpriseEdition ? handleOpenSharing : () => {}}
                size="small"
                disabled={disabled}
              >
                <BankPlus
                  fontSize="small"
                  color={!disabled && isEnterpriseEdition ? 'primary' : 'disabled'}
                />
              </ToggleButton>
            </EETooltip>
          )}
          <Formik
            initialValues={{ objectOrganization: { value: '', label: '' } }}
            onSubmit={onSubmitOrganizations}
            onReset={handleClose || handleCloseSharing}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Dialog
                open={open || displaySharing}
                onClose={() => handleReset()}
                title={t_i18n('Share with an organization')}
              >
                <Form>
                  <ObjectOrganizationField
                    name="objectOrganization"
                    style={{ width: '100%' }}
                    label={t_i18n('Organization')}
                    multiple={false}
                  />
                </Form>
                <DialogActions>
                  <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                    {t_i18n('Close')}
                  </Button>
                  <Button
                    onClick={submitForm}
                    disabled={isSubmitting}
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
        {!handleClose && (
          <>
            <EETooltip title={t_i18n('Share with an organization')}>
              <IconButton
                color="primary"
                aria-label="Label"
                onClick={isEnterpriseEdition ? handleOpenSharing : () => {}}
                style={{ float: 'left', margin: '-15px 0 0 -2px' }}
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
          </>
        )
        }
        <div className="clearfix" />
        <Formik
          initialValues={{ objectOrganization: { value: '', label: '' } }}
          onSubmit={onSubmitOrganizations}
          onReset={handleClose || handleCloseSharing}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Dialog
              open={open || displaySharing}
              onClose={() => handleReset()}
              title={t_i18n('Share with an organization')}
            >
              <Form>
                <ObjectOrganizationField
                  name="objectOrganization"
                  style={{ width: '100%' }}
                  label={t_i18n('Organization')}
                  multiple={false}
                />
              </Form>
              <DialogActions>
                <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Close')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
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
