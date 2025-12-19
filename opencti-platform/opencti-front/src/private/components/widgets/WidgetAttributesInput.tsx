import React, { FunctionComponent, useEffect, useRef } from 'react';
import InputLabel from '@mui/material/InputLabel';
import Tooltip from '@mui/material/Tooltip';
import MenuItem from '@mui/material/MenuItem';
import MuiTextField from '@mui/material/TextField';
import IconButton from '@common/button/IconButton';
import Select from '@mui/material/Select';
import FormControl from '@mui/material/FormControl';
import { DeleteOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import * as Yup from 'yup';
import { Field, FieldArray, Form, Formik } from 'formik';
import { InformationOutline } from 'mdi-material-ui';
import useWidgetConfigValidateForm, { fintelTemplateVariableNameChecker } from '@components/widgets/useWidgetConfigValidateForm';
import { useWidgetConfigContext } from '@components/widgets/WidgetConfigContext';
import FormHelperText from '@mui/material/FormHelperText';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import InputAdornment from '@mui/material/InputAdornment';
import { widgetAttributesInputInstanceQuery } from './WidgetAttributesInputContainer';
import { WidgetAttributesInputContainerInstanceQuery } from './__generated__/WidgetAttributesInputContainerInstanceQuery.graphql';
import { useFormatter } from '../../../components/i18n';
import type { WidgetColumn } from '../../../utils/widget/widget';
import TextField from '../../../components/TextField';
import type { Theme } from '../../../components/Theme';
import { toCamelCase } from '../../../utils/String';
import DeleteDialog from '../../../components/DeleteDialog';
import useDeletion from '../../../utils/hooks/useDeletion';

const stixCoreObjectsAvailableAttributesColumns: { attribute: string; label: string }[] = [
  { attribute: 'representative.main', label: 'Representative' },
  { attribute: 'representative.secondary', label: 'Description' },
  { attribute: 'entity_type', label: 'Entity type' },
  { attribute: 'created_at', label: 'Creation date' },
  { attribute: 'updated_at', label: 'Modification date' },
  { attribute: 'createdBy.name', label: 'Author' },
  { attribute: 'objectMarking.definition', label: 'Markings' },
  { attribute: 'creators.name', label: 'Creators' },
  { attribute: 'objectLabel.value', label: 'Labels' },
  { attribute: 'externalReferences.edges.node.url', label: 'External references URL' },
  { attribute: 'confidence', label: 'Confidence level' },
  { attribute: 'createdBy.x_opencti_reliability', label: 'Reliability (of author)' },
];

const attributesByEntityType: Map<string, { attribute: string; label: string }[]> = new Map([
  ['Attack-Pattern', [
    { attribute: 'x_mitre_id', label: 'External ID' },
  ]],
  ['Campaign', [
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
  ]],
  ['Case-Rfi', [
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'priority', label: 'Priority' },
    { attribute: 'information_types', label: 'Information types' },
  ]],
  ['Case-Rft', [
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'priority', label: 'Priority' },
    { attribute: 'takedown_types', label: 'Takedown types' },
  ]],
  ['Grouping', [
    { attribute: 'context', label: 'Context' },
  ]],
  ['Incident', [
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
  ]],
  ['Case-Incident', [
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'priority', label: 'Priority' },
    { attribute: 'response_types', label: 'Incident type' },
  ]],
  ['Intrusion-Set', [
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
  ]],
  ['Malware', [
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
  ]],
  ['Report', [
    { attribute: 'published', label: 'Report publication date' },
    { attribute: 'report_types', label: 'Report types' },
    { attribute: 'x_opencti_reliability', label: 'Reliability (self)' },
  ]],
  ['Task', [
    { attribute: 'due_date', label: 'Due date' },
  ]],
  ['Threat-Actor-Group', [
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
  ]],
  ['Threat-Actor-Individual', [
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
  ]],
  ['Indicator', [
    { attribute: 'indicator_types', label: 'Indicator types' },
  ]],
  ['Note', [
    { attribute: 'attribute_abstract', label: 'Attribute abstract' },
  ]],
]);

interface WidgetAttributesInputValue {
  attributes: WidgetColumn[];
}

interface WidgetCreationAttributesProps {
  value: readonly WidgetColumn[];
  onChange: (value: WidgetColumn[]) => void;
  queryRef: PreloadedQuery<WidgetAttributesInputContainerInstanceQuery>;
}

const WidgetAttributesInput: FunctionComponent<WidgetCreationAttributesProps> = ({
  value,
  onChange,
  queryRef,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { config, fintelEntityType, fintelEditorValue } = useWidgetConfigContext();
  const { isVarNameAlreadyUsed } = useWidgetConfigValidateForm();

  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;

  const { stixCoreObject } = usePreloadedQuery<WidgetAttributesInputContainerInstanceQuery>(
    widgetAttributesInputInstanceQuery,
    queryRef,
  );
  const entityType = stixCoreObject?.entity_type ?? fintelEntityType;

  const specificAttributesOfType = attributesByEntityType.get(entityType ?? '') ?? [];
  const availableAttributes: { attribute: string; label: string }[] = stixCoreObjectsAvailableAttributesColumns
    .concat(specificAttributesOfType)
    .sort((a, b) => a.label.localeCompare(b.label));

  const findAttribute = (attributeName: string | null) => {
    return availableAttributes.find((a) => a.attribute === attributeName);
  };

  const isWidgetUsedInTemplate = (widgetVarName: string) => {
    return widgetVarName !== '' && !!fintelEditorValue?.includes(`$${widgetVarName}`);
  };

  const attributesValidation = Yup.object({
    attributes: Yup.array().of(
      Yup.object().shape({
        variableName: Yup.string()
          .test('no-space', 'This field cannot contain spaces', (v) => !v?.includes(' '))
          .matches(fintelTemplateVariableNameChecker, t_i18n('The variable name should not contain special characters'))
          .required(t_i18n('This field is required')),
      }),
    ),
  });

  return (
    <div style={{ flex: 1, width: '100%', marginTop: 20 }}>
      <InputLabel sx={{ marginBottom: 1 }}>
        <>
          <>{t_i18n('List of attributes')}</>
          <Tooltip title={(
            <>
              <span style={{ display: 'block', marginBottom: theme.spacing(1) }}>
                {t_i18n('Variable names are identifiers to copy paste in the content to display the corresponding attribute.')}
              </span>
              <span>{t_i18n('Labels are helper texts to better explain the variable names. They are displayed only in the list at the right of your screen.')}</span>
            </>
          )}
          >
            <InformationOutline
              fontSize="small"
              color="primary"
              style={{ margin: '0 0 -5px 8px' }}
            />
          </Tooltip>
        </>
      </InputLabel>

      <Formik<WidgetAttributesInputValue>
        validationSchema={attributesValidation}
        onSubmit={() => {}}
        initialValues={{
          attributes: value.map((column) => ({
            variableName: column.variableName ?? column.attribute,
            label: column.label ?? '',
            attribute: column.attribute,
          })),
        }}
      >
        {({ values }) => {
          const toRemove = useRef<() => void>(undefined);
          const removeAttribute = () => {
            toRemove.current?.();
            toRemove.current = undefined;
            handleCloseDelete();
          };

          useEffect(() => {
            onChange(values.attributes);
          }, [values]);

          const filteredAttributes = availableAttributes.filter((attribute) => {
            return !values.attributes.map((a) => a.attribute).includes(attribute.attribute);
          });

          return (
            <Form>
              <FieldArray name="attributes">
                {({ insert, remove }) => {
                  return (
                    <>
                      {values.attributes.map((row, index) => (
                        <div
                          key={row.attribute}
                          style={{
                            display: 'flex',
                            gap: theme.spacing(2),
                            marginBottom: theme.spacing(2),
                          }}
                        >
                          <MuiTextField
                            label={t_i18n('Attribute')}
                            value={findAttribute(row.attribute)?.label ?? ''}
                            disabled
                            sx={{ flex: 1 }}
                          />
                          <Field
                            component={TextField}
                            name={`attributes[${index}].label`}
                            label={t_i18n('Label')}
                            sx={{ flex: 1 }}
                          />
                          <Field
                            component={TextField}
                            name={`attributes[${index}].variableName`}
                            label={t_i18n('Variable name')}
                            sx={{ flex: 1 }}
                            error={isVarNameAlreadyUsed(values.attributes[index].variableName)}
                            startAdornment={<InputAdornment position="start">$</InputAdornment>}
                            helperText={isVarNameAlreadyUsed(values.attributes[index].variableName)
                              ? t_i18n('This name is already used for an other widget')
                              : undefined
                            }
                          />

                          <Tooltip title={t_i18n('Remove attribute')}>
                            <IconButton
                              size="small"
                              color="primary"
                              sx={{ alignSelf: 'center' }}
                              onClick={() => {
                                if (isWidgetUsedInTemplate(values.attributes[index].variableName ?? '')) {
                                  toRemove.current = () => remove(index);
                                  handleOpenDelete();
                                } else {
                                  remove(index);
                                }
                              }}
                            >
                              <DeleteOutlined fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </div>
                      ))}

                      <div style={{ display: 'flex', gap: theme.spacing(2) }}>
                        <FormControl sx={{ flex: 1 }}>
                          <InputLabel>{t_i18n('Attribute')}</InputLabel>
                          <Select
                            label={t_i18n('Attribute')}
                            sx={{ flex: 1 }}
                            value=""
                            disabled={!config.widget.dataSelection[0].instance_id}
                            onChange={({ target }) => {
                              const attribute = findAttribute(target.value as string);
                              if (attribute) {
                                insert(values.attributes.length, {
                                  ...attribute,
                                  variableName: toCamelCase(attribute.label),
                                });
                              }
                            }}
                          >
                            {filteredAttributes.map((v) => (
                              <MenuItem key={v.attribute} value={v.attribute ?? ''}>
                                {t_i18n(v.label)}
                              </MenuItem>
                            ))}
                          </Select>
                          {!config.widget.dataSelection[0].instance_id && (
                            <FormHelperText>
                              {t_i18n('Select an instance above to be able to choose attributes')}
                            </FormHelperText>
                          )}
                        </FormControl>
                        <MuiTextField
                          label={t_i18n('Label')}
                          disabled
                          sx={{ flex: 1 }}
                        />
                        <MuiTextField
                          label={t_i18n('Variable name')}
                          disabled
                          sx={{ flex: 1 }}
                          slotProps={{
                            input: {
                              startAdornment: <InputAdornment position="start">$</InputAdornment>,
                            },
                          }}
                        />
                        <IconButton size="small" color="primary" disabled>
                          <DeleteOutlined fontSize="small" />
                        </IconButton>
                      </div>

                      <DeleteDialog
                        deletion={deletion}
                        submitDelete={removeAttribute}
                        message={t_i18n('Do you want to delete this attribute?')}
                        warning={{ message: t_i18n('You are about to delete an attribute used in the template') }}
                      />
                    </>
                  );
                }}
              </FieldArray>
            </Form>
          );
        }}
      </Formik>
    </div>
  );
};

export default WidgetAttributesInput;
