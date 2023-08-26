import React, { FunctionComponent } from 'react';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import MenuItem from '@mui/material/MenuItem';
import Alert from '@mui/material/Alert';
import DialogContentText from '@mui/material/DialogContentText';
import AlertTitle from '@mui/material/AlertTitle';
import { makeStyles } from '@mui/styles';
import { Field, FieldArray, Form, Formik } from 'formik';
import { FormikHelpers } from 'formik/dist/types';
import { ArrayHelpers } from 'formik/dist/FieldArray';
import { Add, Delete } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import { graphql, useFragment, useMutation } from 'react-relay';
import FormHelperText from '@mui/material/FormHelperText';
import { useFormatter } from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import Transition from '../../../components/Transition';
import ObjectMembersField from '../common/form/ObjectMembersField';
import SelectField from '../../../components/SelectField';
import { WorkspaceManageAccessDialog_authorizedMembers$key } from './__generated__/WorkspaceManageAccessDialog_authorizedMembers.graphql';
import { handleErrorInForm } from '../../../relay/environment';
import useAuth from '../../../utils/hooks/useAuth';

const useStyles = makeStyles(() => ({
  message: {
    width: '100%',
    overflow: 'hidden',
  },
  subtitle: {
    fontSize: 14,
    marginTop: 16,
    marginBottom: 0,
    fontWeight: 500,
  },
}));

const workspaceManageAccessDialogEditAuthorizedMembersMutation = graphql`
  mutation WorkspaceManageAccessDialogEditAuthorizedMembersMutation(
    $id: ID!
    $input: [MemberAccessInput!]!
  ) {
    workspaceEditAuthorizedMembers(id: $id, input: $input) {
      id
      ...WorkspaceManageAccessDialog_authorizedMembers
    }
  }
`;

const workspaceManageAccessDialogAuthorizedMembersFragment = graphql`
  fragment WorkspaceManageAccessDialog_authorizedMembers on Workspace {
    authorizedMembers {
      id
      name
      entity_type
      access_right
    }
  }
`;

interface Creator {
  id: string;
  name: string;
  entity_type: string;
}

interface MemberAccess {
  id: string;
  name: string;
  entity_type: string;
  access_right: string;
}

interface MembersForm {
  authorizedMembers: MemberAccess[];
  objectMember: { value: string; label: string; type: string };
  objectMemberAccessRight: string;
}

interface WorkspaceManageAccessDialogProps {
  workspaceId: string;
  authorizedMembersData: WorkspaceManageAccessDialog_authorizedMembers$key;
  owner: Creator;
  handleClose: () => void;
  open: boolean;
}

const WorkspaceManageAccessDialog: FunctionComponent<
WorkspaceManageAccessDialogProps
> = ({ workspaceId, authorizedMembersData, owner, handleClose, open }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const { me } = useAuth();

  const [commit] = useMutation(
    workspaceManageAccessDialogEditAuthorizedMembersMutation,
  );

  const data = useFragment<WorkspaceManageAccessDialog_authorizedMembers$key>(
    workspaceManageAccessDialogAuthorizedMembersFragment,
    authorizedMembersData,
  );
  const authorizedMembers = data ? data.authorizedMembers : [];

  const allMemberAccess = {
    id: 'ALL',
    name: t('Everyone on the platform'),
    entity_type: 'all-users',
    access_right: 'none',
  };
  const getInitialAuthorizedMembers = () => {
    const initialAuthorizedMembers: MemberAccess[] = authorizedMembers
      ? authorizedMembers.map((member) => {
        return { ...member } as MemberAccess;
      })
      : [];
    const allMemberDefault = { ...allMemberAccess };
    if (!initialAuthorizedMembers.length) {
      // empty, no restricted access
      // add owner as admin
      initialAuthorizedMembers.push({
        id: owner.id,
        name: owner.name,
        entity_type: owner.entity_type,
        access_right: 'admin',
      });
      // everyone is admin by default
      allMemberDefault.access_right = 'admin';
    }
    const allMember = initialAuthorizedMembers.find(
      (e) => e.id === allMemberAccess.id,
    );
    if (!allMember) {
      initialAuthorizedMembers.unshift(allMemberDefault);
    } else {
      allMember.name = allMemberAccess.name;
      allMember.entity_type = allMemberAccess.entity_type;
    }
    return initialAuthorizedMembers;
  };

  const initialValues = {
    objectMember: {
      value: '',
      label: '',
      type: '',
    },
    objectMemberAccessRight: 'edit',
    authorizedMembers: getInitialAuthorizedMembers(),
  };

  const onAddMember = (
    values: MembersForm,
    arrayHelpers: ArrayHelpers,
    setFieldValue: (
      field: string,
      value: { value: string; label: string; type: string }
    ) => void,
  ) => {
    if (
      values.objectMember
      && values.objectMember.value
      && values.objectMemberAccessRight
      && !values.authorizedMembers.find(
        (node) => node.id === values.objectMember.value,
      )
    ) {
      arrayHelpers.push({
        id: values.objectMember.value,
        name: values.objectMember.label,
        entity_type: values.objectMember.type,
        access_right: values.objectMemberAccessRight,
      });
      // reset object member field value
      setFieldValue('objectMember', { value: '', label: '', type: '' });
    }
  };
  const onSubmitForm = (
    values: MembersForm,
    { setSubmitting, resetForm, setErrors }: FormikHelpers<MembersForm>,
  ) => {
    const finalValues = values.authorizedMembers
      .filter((item, index, array) => {
        return array.findIndex((member) => member.id === item.id) === index;
      })
      .map((member) => {
        return {
          id: member.id,
          access_right: member.access_right,
        };
      });
    commit({
      variables: {
        id: workspaceId,
        input: finalValues,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const accessRights = [
    { label: t('can view'), value: 'view' },
    { label: t('can edit'), value: 'edit' },
    { label: t('can manage'), value: 'admin' },
  ];
  const noAccessRight = { label: t('no access'), value: 'none' };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      onSubmit={onSubmitForm}
    >
      {({
        submitForm,
        isSubmitting,
        dirty,
        values,
        handleReset,
        setFieldValue,
      }) => (
        <Dialog
          open={open}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          maxWidth="sm"
          fullWidth={true}
          onClose={() => {
            handleReset();
            handleClose();
          }}
        >
          <DialogTitle>{t('Manage access')}</DialogTitle>
          <DialogContent>
            <Form>
              <FieldArray
                name="authorizedMembers"
                render={(arrayHelpers) => (
                  <div>
                    <Alert
                      classes={{ message: classes.message }}
                      severity="info"
                      icon={false}
                      variant="outlined"
                      style={{
                        width: '100%',
                        position: 'relative',
                        paddingBottom: '16px',
                      }}
                    >
                      <AlertTitle>{t('Add new access')}</AlertTitle>
                      <div style={{ display: 'flex' }}>
                        <div style={{ flex: 1, paddingRight: '16px' }}>
                          <ObjectMembersField name={'objectMember'} />
                          <FormHelperText style={{ position: 'absolute' }}>
                            {values.authorizedMembers?.find(
                              (node) => node.id === values.objectMember?.value,
                            )
                              ? t('Access already granted')
                              : ''}
                          </FormHelperText>
                        </div>
                        <div style={{ paddingRight: '8px' }}>
                          <Field
                            component={SelectField}
                            name="objectMemberAccessRight"
                            label={t('Access right')}
                            style={{ m: 1, minWidth: 120 }}
                            size="small"
                          >
                            {accessRights.map((accessRight) => {
                              return (
                                <MenuItem
                                  value={accessRight.value}
                                  key={accessRight.value}
                                >
                                  {accessRight.label}
                                </MenuItem>
                              );
                            })}
                          </Field>
                        </div>
                        <div style={{ alignSelf: 'end' }}>
                          <IconButton
                            color="secondary"
                            aria-tag="More"
                            disabled={!values.objectMember?.value}
                            onClick={() => onAddMember(values, arrayHelpers, setFieldValue)
                            }
                          >
                            <Add fontSize="small" />
                          </IconButton>
                        </div>
                      </div>
                    </Alert>
                    <DialogContentText>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        classes={{ root: classes.subtitle }}
                      >
                        {t('Current members access')}
                      </Typography>
                    </DialogContentText>
                    <List style={{ marginBottom: 0 }}>
                      {values.authorizedMembers.map(
                        (authorizedMember, index) => (
                          <ListItem
                            key={authorizedMember.id}
                            dense={true}
                            divider={false}
                          >
                            <ListItemIcon>
                              <ItemIcon type={authorizedMember.entity_type} />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <div>
                                  {authorizedMember.name
                                  && authorizedMember.entity_type ? (
                                      authorizedMember.name
                                    ) : (
                                    <span
                                      style={{
                                        opacity: 0.6,
                                        fontStyle: 'italic',
                                      }}
                                    >
                                      {t('Deleted or restricted member')}
                                    </span>
                                    )}
                                  <span
                                    style={{
                                      opacity: 0.6,
                                      fontStyle: 'italic',
                                    }}
                                  >
                                    {authorizedMember.id === me.id
                                      ? ` (${t('you')})`
                                      : ''}{' '}
                                    {authorizedMember.id === owner.id
                                      ? ` - ${t('Creator')}`
                                      : ''}
                                  </span>
                                </div>
                              }
                            />
                            <Field
                              component={SelectField}
                              name={`authorizedMembers[${index}].access_right`}
                              sx={{ m: 1, minWidth: 120 }}
                              inputProps={{ 'aria-label': 'Without label' }}
                              disabled={authorizedMember.id === me.id}
                              size="small"
                              disableUnderline
                            >
                              {authorizedMember.id === allMemberAccess.id && (
                                <MenuItem
                                  value={noAccessRight.value}
                                  key={noAccessRight.value}
                                >
                                  {noAccessRight.label}
                                </MenuItem>
                              )}
                              {accessRights.map((accessRight) => {
                                return (
                                  <MenuItem
                                    value={accessRight.value}
                                    key={accessRight.value}
                                  >
                                    {accessRight.label}
                                  </MenuItem>
                                );
                              })}
                            </Field>
                            {authorizedMember.id !== allMemberAccess.id
                            && authorizedMember.id !== me.id ? (
                              <IconButton
                                color="primary"
                                aria-tag="delete"
                                onClick={() => arrayHelpers.remove(index)}
                              >
                                <Delete fontSize="small" />
                              </IconButton>
                              ) : (
                              <div style={{ width: 36 }}></div>
                              )}
                          </ListItem>
                        ),
                      )}
                    </List>
                  </div>
                )}
              />
            </Form>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={() => {
                handleReset();
                handleClose();
              }}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting || !dirty || !!values.objectMember?.value}
            >
              {t('Save')}
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Formik>
  );
};

export default WorkspaceManageAccessDialog;
