import { ExpandMore } from '@mui/icons-material';
import { Accordion, AccordionDetails, AccordionSummary, Box, FormControlLabel, Switch, TextField, Typography } from '@mui/material';
import { Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { Field, Formik, useFormikContext } from 'formik';
import React, { useEffect, useRef } from 'react';
import { useFormatter } from '../../../../components/i18n';
import type { AuthorizedMemberOption } from '../../../../utils/authorizedMembers';
import { FieldOption } from '../../../../utils/field';
import AuthorizedMembersField from '../../common/form/AuthorizedMembersField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import CreatedByField from '@components/common/form/CreatedByField';
import type { FormBuilderData } from './Form.d';
import { normalizeDraftAuthorizedMembersDefaults } from './FormUtils';

type DraftAdvancedDefaultsValues = {
  objectAssignee: FieldOption[];
  objectParticipant: FieldOption[];
};

const DraftAdvancedDefaultsSync = ({ onChange }: { onChange: (vals: DraftAdvancedDefaultsValues) => void }) => {
  const { values } = useFormikContext<DraftAdvancedDefaultsValues>();
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  useEffect(() => {
    onChangeRef.current(values);
  }, [values]);
  return null;
};

type AuthorizedMembersDefaultsValues = { authorized_members: AuthorizedMemberOption[] };

const AuthorizedMembersSync = ({ onChange }: { onChange: (vals: AuthorizedMemberOption[]) => void }) => {
  const { values } = useFormikContext<AuthorizedMembersDefaultsValues>();
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  useEffect(() => {
    onChangeRef.current(values.authorized_members);
  }, [values.authorized_members]);
  return null;
};

const normalizeFieldOption = (option: FieldOption) => {
  return {
    value: option.value,
    label: option.label,
  };
};

const areFieldOptionsEqual = (left: FieldOption[], right: FieldOption[]) => {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((leftOption, index) => {
    const normalizedLeft = normalizeFieldOption(leftOption);
    const normalizedRight = normalizeFieldOption(right[index]);
    return normalizedLeft.value === normalizedRight.value && normalizedLeft.label === normalizedRight.label;
  });
};

const normalizeAuthorizedMember = (member: AuthorizedMemberOption) => {
  return {
    value: member.value,
    label: member.label,
    type: member.type,
    accessRight: member.accessRight,
    groupsRestriction: (member.groupsRestriction || [])
      .map(normalizeFieldOption)
      .sort((a, b) => `${a.value}`.localeCompare(`${b.value}`)),
  };
};

const areAuthorizedMembersEqual = (left: AuthorizedMemberOption[], right: AuthorizedMemberOption[]) => {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((leftMember, index) => {
    const normalizedLeft = normalizeAuthorizedMember(leftMember);
    const normalizedRight = normalizeAuthorizedMember(right[index]);
    return (
      normalizedLeft.value === normalizedRight.value
      && normalizedLeft.label === normalizedRight.label
      && normalizedLeft.type === normalizedRight.type
      && normalizedLeft.accessRight === normalizedRight.accessRight
      && areFieldOptionsEqual(normalizedLeft.groupsRestriction, normalizedRight.groupsRestriction)
    );
  });
};

export interface DraftDefaultsSectionProps {
  formData: FormBuilderData;
  handleFieldChange: (path: string, value: unknown) => void;
}

const DraftDefaultsSection: React.FC<DraftDefaultsSectionProps> = ({ formData, handleFieldChange }) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <FormControlLabel
        control={(
          <Switch
            checked={formData.isDraftByDefault}
            onChange={(e) => handleFieldChange('isDraftByDefault', e.target.checked)}
          />
        )}
        label={t_i18n('Create as draft by default')}
      />

      {formData.isDraftByDefault && (
        <FormControlLabel
          control={(
            <Switch
              checked={formData.allowDraftOverride}
              onChange={(e) => handleFieldChange('allowDraftOverride', e.target.checked)}
            />
          )}
          label={t_i18n('Allow users to uncheck draft mode')}
        />
      )}

      <Accordion
        variant="outlined"
        disableGutters
        sx={{
          backgroundColor: 'transparent',
          border: '1px solid var(--border-elevation-subtle)',
          borderRadius: '4px',
        }}
      >
        <AccordionSummary expandIcon={<ExpandMore />}>
          <Typography>{t_i18n('Advanced Draft Settings')}</Typography>
        </AccordionSummary>
        <AccordionDetails>
          {/* Draft Name Section */}
          <Typography variant="h6" gutterBottom>{t_i18n('Draft Name')}</Typography>
          <Box style={{ paddingTop: 10 }}>
            <FormControlLabel
              control={(
                <Switch
                  checked={formData.draftDefaults?.name?.isEditable || false}
                  onChange={(e) => handleFieldChange('draftDefaults.name.isEditable', e.target.checked)}
                />
              )}
              label={t_i18n('Editable by end user')}
              style={{ display: 'block' }}
            />
            {formData.draftDefaults?.name?.isEditable && (
              <FormControlLabel
                control={(
                  <Switch
                    checked={formData.draftDefaults?.name?.isRequired || false}
                    onChange={(e) => handleFieldChange('draftDefaults.name.isRequired', e.target.checked)}
                  />
                )}
                label={t_i18n('Required')}
                style={{ display: 'block' }}
              />
            )}
            <TextField
              fullWidth
              variant="outlined"
              label={t_i18n('Default name')}
              value={formData.draftDefaults?.name?.defaultValue || ''}
              onChange={(e) => handleFieldChange('draftDefaults.name.defaultValue', e.target.value)}
              className="mb-5"
            />
          </Box>

          {/* Draft Description Section */}
          <Typography variant="h6" gutterBottom>{t_i18n('Draft Description')}</Typography>
          <Box style={{ paddingTop: 10 }}>
            <FormControlLabel
              control={(
                <Switch
                  checked={formData.draftDefaults?.description?.isEditable || false}
                  onChange={(e) => handleFieldChange('draftDefaults.description.isEditable', e.target.checked)}
                />
              )}
              label={t_i18n('Editable by end user')}
              style={{ display: 'block' }}
            />
            {formData.draftDefaults?.description?.isEditable && (
              <FormControlLabel
                control={(
                  <Switch
                    checked={formData.draftDefaults?.description?.isRequired || false}
                    onChange={(e) => handleFieldChange('draftDefaults.description.isRequired', e.target.checked)}
                  />
                )}
                label={t_i18n('Required')}
                style={{ display: 'block' }}
              />
            )}
            <TextField
              fullWidth
              variant="outlined"
              label={t_i18n('Default description')}
              multiline
              rows={3}
              value={formData.draftDefaults?.description?.defaultValue || ''}
              onChange={(e) => handleFieldChange('draftDefaults.description.defaultValue', e.target.value)}
              style={{ marginBottom: 20 }}
            />
          </Box>

          <Formik
            initialValues={{
              objectAssignee: formData.draftDefaults?.objectAssignee?.defaults || [],
              objectParticipant: formData.draftDefaults?.objectParticipant?.defaults || [],
              authorDefaultIdentity: (formData.draftDefaults?.author?.type === 'static' && formData.draftDefaults.author.defaultValue)
                ? {
                    value: formData.draftDefaults.author.defaultValue,
                    label: formData.draftDefaults.author.defaultValueLabel || formData.draftDefaults.author.defaultValue,
                    type: formData.draftDefaults.author.defaultValueType,
                  }
                : null,
            }}
            onSubmit={() => {}}
            enableReinitialize
          >
            {({ setFieldValue }) => (
              <>
                {/* Draft Assignees Section */}
                <Typography variant="h6" gutterBottom>{t_i18n('Draft Assignees')}</Typography>
                <Box style={{ paddingTop: 10 }}>
                  <FormControlLabel
                    control={(
                      <Switch
                        checked={formData.draftDefaults?.objectAssignee?.isEditable || false}
                        onChange={(e) => handleFieldChange('draftDefaults.objectAssignee.isEditable', e.target.checked)}
                      />
                    )}
                    label={t_i18n('Editable by end user')}
                    style={{ display: 'block' }}
                  />
                  {formData.draftDefaults?.objectAssignee?.isEditable && (
                    <FormControlLabel
                      control={(
                        <Switch
                          checked={formData.draftDefaults?.objectAssignee?.isRequired || false}
                          onChange={(e) => handleFieldChange('draftDefaults.objectAssignee.isRequired', e.target.checked)}
                        />
                      )}
                      label={t_i18n('Required')}
                      style={{ display: 'block' }}
                    />
                  )}
                  <ObjectAssigneeField
                    name="objectAssignee"
                    label={t_i18n('Default assignee(s)')}
                    style={{ marginBottom: 20 }}
                  />
                </Box>

                {/* Draft Participants Section */}
                <Typography variant="h6" gutterBottom>{t_i18n('Draft Participants')}</Typography>
                <Box style={{ paddingTop: 10 }}>
                  <FormControlLabel
                    control={(
                      <Switch
                        checked={formData.draftDefaults?.objectParticipant?.isEditable || false}
                        onChange={(e) => handleFieldChange('draftDefaults.objectParticipant.isEditable', e.target.checked)}
                      />
                    )}
                    label={t_i18n('Editable by end user')}
                    style={{ display: 'block' }}
                  />
                  {formData.draftDefaults?.objectParticipant?.isEditable && (
                    <FormControlLabel
                      control={(
                        <Switch
                          checked={formData.draftDefaults?.objectParticipant?.isRequired || false}
                          onChange={(e) => handleFieldChange('draftDefaults.objectParticipant.isRequired', e.target.checked)}
                        />
                      )}
                      label={t_i18n('Required')}
                      style={{ display: 'block' }}
                    />
                  )}
                  <ObjectParticipantField
                    name="objectParticipant"
                    label={t_i18n('Default participants')}
                    style={{ marginBottom: 20 }}
                  />
                </Box>

                {/* Draft Author Section */}
                <Typography variant="h6" gutterBottom>{t_i18n('Draft Author')}</Typography>
                <Box style={{ paddingTop: 10 }}>
                  <FormControlLabel
                    control={(
                      <Switch
                        checked={formData.draftDefaults?.author?.isEditable || false}
                        onChange={(e) => handleFieldChange('draftDefaults.author.isEditable', e.target.checked)}
                      />
                    )}
                    label={t_i18n('Editable by end user')}
                    style={{ display: 'block' }}
                  />
                  {formData.draftDefaults?.author?.isEditable && (
                    <FormControlLabel
                      control={(
                        <Switch
                          checked={formData.draftDefaults?.author?.isRequired || false}
                          onChange={(e) => handleFieldChange('draftDefaults.author.isRequired', e.target.checked)}
                        />
                      )}
                      label={t_i18n('Required')}
                      style={{ display: 'block' }}
                    />
                  )}
                  <Box
                    style={formData.draftDefaults?.author?.type === 'static'
                      ? {
                          border: '1px solid var(--border-elevation-subtle)',
                          borderRadius: 4,
                          padding: '12px',
                          marginBottom: 20,
                        }
                      : { marginBottom: 20 }}
                  >
                    <Select
                      value={formData.draftDefaults?.author?.type || 'none'}
                      onValueChange={(value) => {
                        const currentAuthorDefaults = formData.draftDefaults?.author;
                        handleFieldChange('draftDefaults.author', {
                          type: value,
                          isEditable: currentAuthorDefaults?.isEditable ?? false,
                          isRequired: currentAuthorDefaults?.isRequired ?? false,
                        });
                      }}
                    >
                      <SelectLabel>{t_i18n('Default author source')}</SelectLabel>
                      <SelectTrigger className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent aria-label={t_i18n('Default author source')}>
                        <SelectItem value="none">{t_i18n('None (no author specified)')}</SelectItem>
                        <SelectItem value="main_entity_author">{t_i18n('Main entity author (reuse the same author)')}</SelectItem>
                        <SelectItem value="static">{t_i18n('Specific Author')}</SelectItem>
                      </SelectContent>
                    </Select>
                    {formData.draftDefaults?.author?.type === 'static' && (
                      <CreatedByField
                        name="authorDefaultIdentity"
                        label={t_i18n('Default author')}
                        style={{ width: '100%', marginBottom: 0 }}
                        setFieldValue={setFieldValue}
                        onChange={(_name: string, value: { value: string; label: string; type?: string } | null) => {
                          if (value) {
                            handleFieldChange('draftDefaults.author.defaultValue', value.value);
                            handleFieldChange('draftDefaults.author.defaultValueLabel', value.label);
                            handleFieldChange('draftDefaults.author.defaultValueType', value.type);
                          } else {
                            handleFieldChange('draftDefaults.author.defaultValue', undefined);
                            handleFieldChange('draftDefaults.author.defaultValueLabel', undefined);
                            handleFieldChange('draftDefaults.author.defaultValueType', undefined);
                          }
                        }}
                      />
                    )}
                  </Box>
                </Box>

                {/* Authorized Members Section */}
                <Typography variant="h6" gutterBottom style={{ marginTop: 20 }}>{t_i18n('Authorized Members')}</Typography>
                <FormControlLabel
                  control={(
                    <Switch
                      checked={formData.draftDefaults?.authorizedMembers?.enabled || false}
                      onChange={(e) => {
                        const enabled = e.target.checked;
                        handleFieldChange('draftDefaults.authorizedMembers.enabled', enabled);
                        if (enabled && (!formData.draftDefaults?.authorizedMembers?.defaults || formData.draftDefaults?.authorizedMembers?.defaults.length === 0)) {
                          handleFieldChange('draftDefaults.authorizedMembers.defaults', [{
                            label: t_i18n('Creators'),
                            value: 'CREATORS',
                            type: t_i18n('Dynamic options'),
                            accessRight: 'admin',
                            groupsRestriction: [],
                          }]);
                        }
                      }}
                    />
                  )}
                  label={t_i18n('Activate access restriction')}
                  style={{ display: 'block' }}
                />

                {formData.draftDefaults?.authorizedMembers?.enabled && (
                  <Box style={{ paddingTop: 10 }}>
                    <FormControlLabel
                      control={(
                        <Switch
                          checked={formData.draftDefaults?.authorizedMembers?.isEditable || false}
                          onChange={(e) => handleFieldChange('draftDefaults.authorizedMembers.isEditable', e.target.checked)}
                        />
                      )}
                      label={t_i18n('Editable by end user')}
                      style={{ display: 'block', marginBottom: 15 }}
                    />
                    <Typography variant="subtitle2" style={{ marginTop: 10, marginBottom: 10 }}>{t_i18n('Default authorized members')}</Typography>
                    <Formik
                      initialValues={{
                        authorized_members: normalizeDraftAuthorizedMembersDefaults(
                          formData.draftDefaults?.authorizedMembers?.defaults || [],
                          {
                            creatorsLabel: t_i18n('Creators'),
                            authorOrgLabel: t_i18n('Draft author (org)'),
                            dynamicOptionsLabel: t_i18n('Dynamic from draft'),
                          },
                        ),
                      }}
                      onSubmit={() => {}}
                    >
                      {() => (
                        <>
                          <Field
                            name="authorized_members"
                            component={AuthorizedMembersField}
                            withDynamicKeys={true}
                            allowDynamicGroupsRestriction={true}
                            dynamicContextTypeLabel="Dynamic from draft"
                            dynamicAuthorOrgLabel="Draft author (org)"
                            includeBundleOrganizationDynamicOption={false}
                            dynamicGroupsRestrictionSupportedValues={['AUTHOR']}
                          />
                          <AuthorizedMembersSync
                            onChange={(vals) => {
                              if (!areAuthorizedMembersEqual(formData.draftDefaults?.authorizedMembers?.defaults || [], vals)) {
                                handleFieldChange('draftDefaults.authorizedMembers.defaults', vals);
                              }
                            }}
                          />
                        </>
                      )}
                    </Formik>
                  </Box>
                )}

                <DraftAdvancedDefaultsSync
                  onChange={(vals) => {
                    if (!areFieldOptionsEqual(formData.draftDefaults?.objectAssignee?.defaults || [], vals.objectAssignee)) {
                      handleFieldChange('draftDefaults.objectAssignee.defaults', vals.objectAssignee);
                    }
                    if (!areFieldOptionsEqual(formData.draftDefaults?.objectParticipant?.defaults || [], vals.objectParticipant)) {
                      handleFieldChange('draftDefaults.objectParticipant.defaults', vals.objectParticipant);
                    }
                  }}
                />
              </>
            )}
          </Formik>
        </AccordionDetails>
      </Accordion>
    </>
  );
};

export default DraftDefaultsSection;
