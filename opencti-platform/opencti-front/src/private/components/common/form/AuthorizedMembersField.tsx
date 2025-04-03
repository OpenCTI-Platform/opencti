import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import ObjectMembersField, { OptionMember } from '@components/common/form/ObjectMembersField';
import FormHelperText from '@mui/material/FormHelperText';
import { Field, FieldArray, FieldProps, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import React, { useState } from 'react';
import * as Yup from 'yup';
import { FormikHelpers } from 'formik/dist/types';
import AuthorizedMembersFieldListItem from '@components/common/form/AuthorizedMembersFieldListItem';
import AccordionDetails from '@mui/material/AccordionDetails';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import { AccessRight, ALL_MEMBERS_AUTHORIZED_CONFIG, AuthorizedMemberOption, Creator, CREATOR_AUTHORIZED_CONFIG } from '../../../../utils/authorizedMembers';
import SwitchField from '../../../../components/fields/SwitchField';
import useAuth from '../../../../utils/hooks/useAuth';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { AutoCompleteOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';

/**
 * Returns true if the authorized member option is generic.
 * Generic option = is not focusing an existing member but
 * instead an unknown member which can changed.
 *
 * @param memberId The ID to check.
 */
export const isGenericOption = (memberId: string) => {
  return [
    ALL_MEMBERS_AUTHORIZED_CONFIG.id,
    CREATOR_AUTHORIZED_CONFIG.id,
  ].includes(memberId);
};

// Type of data of the field in a Formik form.
export type AuthorizedMembersFieldValue = AuthorizedMemberOption[] | null;

interface AuthorizedMembersFieldProps
  extends FieldProps<AuthorizedMembersFieldValue> {
  owner?: Creator;
  showAllMembersLine?: boolean;
  showCreatorLine?: boolean;
  canDeactivate?: boolean;
  addMeUserWithAdminRights?: boolean;
}

// Type of data for internal form, not exposed to others.
interface AuthorizedMembersFieldInternalValue {
  applyAccesses: boolean;
  newAccessMember: AutoCompleteOption | null;
  newAccessRight: AccessRight;
  allAccessRight: AccessRight;
  creatorAccessRight: AccessRight;
  groupsRestriction: OptionMember[];
}

// Validation for the internal formik form.
const formikSchema = Yup.object().shape({
  applyAccesses: Yup.boolean(),
  newAccessMember: Yup.object()
    .shape({
      value: Yup.string().trim().required(),
      label: Yup.string().trim().required(),
      type: Yup.string().trim().required(),
    })
    .required(''),
  newAccessRight: Yup.string().trim().required(''),
});

const AuthorizedMembersField = ({
  form,
  field,
  owner,
  showAllMembersLine = false,
  showCreatorLine = false,
  canDeactivate = false,
  addMeUserWithAdminRights = false,
}: AuthorizedMembersFieldProps) => {
  const { t_i18n } = useFormatter();
  const { setFieldValue } = form;
  const { name, value } = field;
  const { me } = useAuth();
  const draftContext = useDraftContext();

  // Value in sync with internal Formik field 'applyAccesses'.
  // Require to use a state in addition to the Formik field because
  // we use the value outside the scope of the internal Formik form.
  const [applyAccesses, setApplyAccesses] = useState(
    value && Array.isArray(value) && value.length > 0,
  );
  const accessForAllMembers = (value ?? []).find(
    (o) => o.value === ALL_MEMBERS_AUTHORIZED_CONFIG.id,
  );
  const accessForCreator = (value ?? []).find(
    (o) => o.value === CREATOR_AUTHORIZED_CONFIG.id,
  );

  const allMembersOption: AuthorizedMemberOption = {
    label: t_i18n(ALL_MEMBERS_AUTHORIZED_CONFIG.labelKey),
    type: ALL_MEMBERS_AUTHORIZED_CONFIG.type,
    value: ALL_MEMBERS_AUTHORIZED_CONFIG.id,
    groupsRestriction: [],
    accessRight: accessForAllMembers?.accessRight ?? 'none',
  };
  const creatorOption: AuthorizedMemberOption = {
    label: t_i18n(CREATOR_AUTHORIZED_CONFIG.labelKey),
    type: CREATOR_AUTHORIZED_CONFIG.type,
    value: CREATOR_AUTHORIZED_CONFIG.id,
    groupsRestriction: [],
    accessRight: accessForCreator?.accessRight ?? 'none',
  };

  const accessRights = [
    { label: t_i18n('can view'), value: 'view' },
    { label: t_i18n('can edit'), value: 'edit' },
    { label: t_i18n('can manage'), value: 'admin' },
  ];

  /**
   * Add a new authorized member in the value of the field,
   * called when submitting internal Formik form.
   *
   * @param data Data of the authorized member to add.
   * @param helpers Internal Formik helpers to reset inputs.
   */
  const addAuthorizedMembers = (
    data: AuthorizedMembersFieldInternalValue,
    helpers: FormikHelpers<AuthorizedMembersFieldInternalValue>,
  ) => {
    if (data.newAccessRight && data.newAccessMember) {
      setFieldValue(name, [
        ...(value ?? []),
        {
          ...data.newAccessMember,
          accessRight: data.newAccessRight,
          groupsRestriction: data.groupsRestriction,
        },
      ]);
      helpers.setFieldValue('newAccessMember', null);
      helpers.setFieldValue('newAccessRight', 'view');
      helpers.setFieldValue('groupsRestriction', []);
    }
  };

  /**
   * Keep the state applyAccesses in sync with the field of internal
   * Formik form and reset field values. Called when changing the
   * value of the switch 'applyAccesses'.
   *
   * @param val False if it should not apply authorized member accesses.
   * @param resetForm Internal Formik helpers to reset inputs.
   * @param setField Internal Formik helpers to set a specific field.
   */
  const changeApplyAccesses = (
    val: boolean,
    resetForm: FormikHelpers<AuthorizedMembersFieldInternalValue>['resetForm'],
    setField: FormikHelpers<AuthorizedMembersFieldInternalValue>['setFieldValue'],
  ) => {
    setApplyAccesses(val);
    if (!val) {
      setFieldValue(name, null);
      resetForm({
        values: {
          applyAccesses: val,
          newAccessMember: null,
          newAccessRight: 'view',
          allAccessRight: 'none',
          creatorAccessRight: 'none',
          groupsRestriction: [],
        },
      });
    } else {
      const values: AuthorizedMemberOption[] = [];
      if (showCreatorLine) {
        values.push({
          ...creatorOption,
          accessRight: 'admin',
          groupsRestriction: [],
        });
        setField('creatorAccessRight', 'admin');
      }
      if (owner) {
        values.push({
          label: owner.name,
          type: owner.entity_type,
          value: owner.id,
          accessRight: 'admin',
          groupsRestriction: [],
        });
      }
      if (addMeUserWithAdminRights && me.id !== owner?.id) {
        values.push({
          label: me.name,
          type: 'User',
          value: me.id,
          accessRight: 'admin',
          groupsRestriction: [],
        });
      }
      setFieldValue(name, values);
    }
  };

  /**
   * Change the access level of a member in the field value.
   * If the member does not already exist in the field, then add it.
   *
   * If the access level is 'none', remove the member from the field instead.
   *
   * Function called when changing the access level of a generic option as
   * generic options are not managed the same way as others. Because we want
   * them to always been on top of the list and displayed in UI even if no
   * access is granted to them.
   *
   * @param id The id of the member to modify.
   * @param accessRight The new access level for the member.
   */
  const changeMemberAccess = (id: string, accessRight: AccessRight) => {
    if (accessRight === 'none') {
      setFieldValue(name, [
        ...(value ?? []).filter((option) => option.value !== id),
      ]);
    } else {
      let modifiedAccess = value?.find((option) => option.value === id);
      if (!modifiedAccess) {
        modifiedAccess = id === ALL_MEMBERS_AUTHORIZED_CONFIG.id
          ? {
            ...allMembersOption,
            accessRight,
          }
          : {
            ...creatorOption,
            accessRight,
          };
      }
      setFieldValue(name, [
        ...(value ?? []).filter((option) => option.value !== id),
        {
          ...modifiedAccess,
          accessRight,
        },
      ]);
    }
  };

  // To change the access of all members in the platform.
  const changeAllMembersAccess = (accessRight: AccessRight) => {
    changeMemberAccess(ALL_MEMBERS_AUTHORIZED_CONFIG.id, accessRight);
  };

  // To change the access of the creator of the entity.
  const changeCreatorAccess = (accessRight: AccessRight) => {
    changeMemberAccess(CREATOR_AUTHORIZED_CONFIG.id, accessRight);
  };

  let accessInfoMessage = t_i18n('info_authorizedmembers_workspace');
  if (canDeactivate) {
    accessInfoMessage = applyAccesses
      ? t_i18n('info_authorizedmembers_knowledge_off')
      : t_i18n('info_authorizedmembers_knowledge_on');
  }

  const doesNewMemberAlreadyExist = (values: AuthorizedMembersFieldInternalValue) => {
    return value?.some(
      (a) => {
        const sameMember = a.value === values.newAccessMember?.value;
        const sameGroupsLength = a.groupsRestriction.length === values.groupsRestriction.length;
        const sameGroups = sameGroupsLength && a.groupsRestriction.every((g1) => {
          return values.groupsRestriction.find((g2) => g1.value === g2.value);
        });
        return sameMember && sameGroups;
      },
    );
  };

  return (
    <>
      {/* Internal Formik component to be able to use our custom field components */}
      <Formik<AuthorizedMembersFieldInternalValue>
        validationSchema={formikSchema}
        validateOnChange={false}
        validateOnBlur={false}
        initialValues={{
          applyAccesses: applyAccesses ?? false,
          newAccessMember: null,
          newAccessRight: 'view',
          allAccessRight: accessForAllMembers?.accessRight ?? 'none',
          creatorAccessRight: accessForCreator?.accessRight ?? 'none',
          groupsRestriction: [],
        }}
        onSubmit={addAuthorizedMembers}
      >
        {({
          values,
          handleSubmit,
          isValid,
          dirty,
          resetForm,
          setFieldValue: setField,
        }) => (
          <>
            <Alert severity="info">{accessInfoMessage}</Alert>
            {!!draftContext && (
            <Alert style={{ marginTop: 15 }} severity="warning">{t_i18n('Not available in draft')}</Alert>
            )}
            {canDeactivate && (
              <Field
                component={SwitchField}
                containerstyle={{
                  display: 'inline-block',
                  marginTop: 15,
                  paddingLeft: 10,
                }}
                type="checkbox"
                name="applyAccesses"
                label={t_i18n('Activate access restriction')}
                disabled={!!draftContext}
                onChange={(_: string, val: string) => {
                  changeApplyAccesses(val === 'true', resetForm, setField);
                }}
              />
            )}
            {applyAccesses && (
              <Alert
                sx={{
                  mt: '16px',
                  width: '100%',
                  paddingBottom: '16px',
                  '.MuiAlert-message': { width: '100%' },
                }}
                severity="info"
                icon={false}
                variant="outlined"
              >
                <AlertTitle>{t_i18n('Add new specific access')}</AlertTitle>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 16,
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <ObjectMembersField
                      name="newAccessMember"
                      disabled={!values.applyAccesses}
                    />
                    {value?.find(
                      (a) => a.value === values.newAccessMember?.value,
                    ) && (
                      <FormHelperText style={{ position: 'absolute' }}>
                        {t_i18n('Access already granted')}
                      </FormHelperText>
                    )}
                  </div>
                  <Field
                    name="newAccessRight"
                    component={SelectField}
                    label={t_i18n('Access right')}
                    style={{ m: 1, minWidth: 120 }}
                    size="small"
                    disabled={!values.applyAccesses}
                  >
                    {accessRights.map((accessRight) => (
                      <MenuItem
                        value={accessRight.value}
                        key={accessRight.value}
                      >
                        {accessRight.label}
                      </MenuItem>
                    ))}
                  </Field>
                  <IconButton
                    color="secondary"
                    aria-label="More"
                    onClick={() => handleSubmit()}
                    disabled={
                      !dirty
                      || !isValid
                      || doesNewMemberAlreadyExist(values)
                      || !values.applyAccesses
                    }
                    style={{ marginTop: 10 }}
                  >
                    <Add fontSize="small" />
                  </IconButton>
                </div>
                {values.newAccessMember && values.newAccessMember.type === 'Organization' && (
                  <div style={fieldSpacingContainerStyle}>
                    <Accordion>
                      <AccordionSummary id="accordion-panel">
                        <Typography>{t_i18n('Advanced options')}</Typography>
                      </AccordionSummary>
                      <AccordionDetails style={{ padding: 0 }}>
                        <Alert severity="info" style={{ fontSize: 11 }}>
                          {t_i18n('Restrict access by selecting groups to intersect with the organization\'s access rights')}
                        </Alert>
                        <div style={{ padding: '8px 16px 16px 16px' }}>
                          <ObjectMembersField
                            name="groupsRestriction"
                            label={t_i18n('Groups restriction')}
                            disabled={!values.applyAccesses}
                            entityTypes={['Group']}
                            multiple
                          />
                        </div>
                      </AccordionDetails>
                    </Accordion>
                  </div>
                )}
              </Alert>
            )}
            {applyAccesses && (
              <>
                <Typography
                  variant="h3"
                  sx={{
                    fontSize: 14,
                    fontWeight: 500,
                    mt: '16px',
                    mb: 0,
                  }}
                >
                  {t_i18n('Current specific accesses')}
                </Typography>

                <List sx={{ pb: 0 }}>
                  {showAllMembersLine && (
                    <AuthorizedMembersFieldListItem
                      authorizedMember={allMembersOption}
                      name="allAccessRight"
                      accessRights={accessRights}
                      ownerId={owner?.id}
                      onChange={changeAllMembersAccess}
                    />
                  )}
                  {showCreatorLine && (
                    <AuthorizedMembersFieldListItem
                      authorizedMember={creatorOption}
                      name="creatorAccessRight"
                      accessRights={accessRights}
                      ownerId={owner?.id}
                      onChange={changeCreatorAccess}
                    />
                  )}
                </List>
              </>
            )}
          </>
        )}
      </Formik>
      {applyAccesses && (
        <FieldArray
          name={name}
          render={(arrayHelpers) => (
            <>
              {value && value.length > 0 && (
                <List sx={{ pt: 0 }}>
                  {value.map((authorizedMember, index) => (!isGenericOption(authorizedMember.value) ? (
                    <AuthorizedMembersFieldListItem
                      key={index}
                      authorizedMember={authorizedMember}
                      name={`${name}[${index}].accessRight`}
                      accessRights={accessRights}
                      ownerId={owner?.id}
                      onRemove={() => arrayHelpers.remove(index)}
                    />
                  ) : null))}
                </List>
              )}
            </>
          )}
        />
      )}
    </>
  );
};

export default AuthorizedMembersField;
