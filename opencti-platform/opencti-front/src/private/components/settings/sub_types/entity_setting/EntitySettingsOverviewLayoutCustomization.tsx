import React from 'react';
import { graphql, useFragment } from 'react-relay';
import TableContainer from '@mui/material/TableContainer';
import Table from '@mui/material/Table';
import Paper from '@mui/material/Paper';
import TableHead from '@mui/material/TableHead';
import TableCell from '@mui/material/TableCell';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import Switch from '@mui/material/Switch';
import { SubType_subType$data } from '@components/settings/sub_types/__generated__/SubType_subType.graphql';
import {
  EntitySettingsOverviewLayoutCustomization_entitySetting$key,
} from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingsOverviewLayoutCustomization_entitySetting.graphql';
import { Field, Form, Formik } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import useOverviewLayoutCustomization from '../../../../../utils/hooks/useOverviewLayoutCustomization';
import TextField from '../../../../../components/TextField';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';

export const entitySettingsOverviewLayoutCustomizationFragment = graphql`
    fragment EntitySettingsOverviewLayoutCustomization_entitySetting on EntitySetting {
      id
      target_type
      overview_layout_customization {
        key
        width
      }
    }
`;

export const entitySettingsOverviewLayoutCustomizationEdit = graphql`
  mutation EntitySettingsOverviewLayoutCustomizationEditMutation(
    $ids: [ID!]!
    $input: [EditInput!]!
) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      id
      target_type
      overview_layout_customization {
        key
        width
      }
    }
  }
`;

const EntitySettingsOverviewLayoutCustomization = ({
  entitySettingsData,
}: {
  entitySettingsData: SubType_subType$data['settings'];
}) => {
  const { t_i18n } = useFormatter();
  const entitySetting = useFragment<EntitySettingsOverviewLayoutCustomization_entitySetting$key>(
    entitySettingsOverviewLayoutCustomizationFragment,
    entitySettingsData,
  );

  const entitySettingsOverviewLayoutCustomization = useOverviewLayoutCustomization(entitySetting?.target_type ?? '');
  // Since it's a frontend issue, a Map with widget labels by entity type could be used by a dedicated function to enrich config with labels
  const threatActorIndividualOverviewLayoutCustomizationWithLabels = entitySettingsOverviewLayoutCustomization.map(({ key, width }) => {
    switch (key) {
      case 'details':
        return ({ key, width, label: t_i18n('Entity details') });
      case 'basicInformation':
        return ({ key, width, label: t_i18n('Basic information') });
      case 'demographics':
        return ({ key, width, label: t_i18n('Demographics') });
      case 'biographics':
        return ({ key, width, label: t_i18n('Biographics') });
      case 'latestCreatedRelationships':
        return ({ key, width, label: t_i18n('Latest created relationships') });
      case 'latestContainers':
        return ({ key, width, label: t_i18n('Latest containers') });
      case 'externalReferences':
        return ({ key, width, label: t_i18n('External references') });
      case 'mostRecentHistory':
        return ({ key, width, label: t_i18n('Most recent history') });
      case 'notes':
        return ({ key, width, label: t_i18n('Notes about this entity') });
      default:
        return ({ key: '', width: 6, label: '' });
    }
  });

  const initialValues = {
    ...entitySettingsOverviewLayoutCustomization.reduce((accumulator, widgetConfiguration, currentIndex) => ({
      ...accumulator,
      [`${widgetConfiguration.key}_isFullWidth`]: widgetConfiguration.width === 12,
      [`${widgetConfiguration.key}_order`]: currentIndex + 1,
    }), {}),
  };

  const [commitUpdate] = useApiMutation((entitySettingsOverviewLayoutCustomizationEdit));
  const convertToOverviewLayoutCustomizationEditInput = (values: typeof initialValues) => {
    const editInputsKeys = entitySettingsOverviewLayoutCustomization.map(({ key }) => key);
    const editInputsEntries = Object.entries(values);

    return editInputsKeys.map((editInputsKey) => {
      const widgetEditInput = {
        key: editInputsKey,
        order: 0,
        width: 0,
      };
      editInputsEntries.forEach(([entryKey, entryValue]) => {
        if (entryKey.startsWith(editInputsKey) && entryKey.endsWith('isFullWidth')) {
          widgetEditInput.width = entryValue ? 12 : 6;
        }
        if (entryKey.startsWith(editInputsKey) && entryKey.endsWith('order')) {
          widgetEditInput.order = entryValue as unknown as number;
        }
      });
      return widgetEditInput; // TODO: sort by order and return key and width only, on chunk#2 merge
    });
  };
  const updateLayout = (values: typeof initialValues) => {
    const input = {
      key: 'overview_layout_customization',
      value: convertToOverviewLayoutCustomizationEditInput(values),
    };
    commitUpdate({
      variables: {
        ids: [entitySetting?.id],
        input,
      },
    });
  };
  const handleSubmitIsFullWidthField = (values: typeof initialValues) => {
    updateLayout(values);
  };
  const handleSubmitOrderField = (values: typeof initialValues) => {
    updateLayout(values);
  };

  if (!entitySetting?.overview_layout_customization) {
    return null;
  }

  return (
    <Formik<typeof initialValues>
      enableReinitialize={true}
      initialValues={initialValues}
      onSubmit={() => {}}
    >
      {({
        values,
        setFieldValue,
      }) => (
        <Form>
          <TableContainer component={Paper}>
            <Table aria-label={t_i18n('Overview layout customization configuration table')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Widget')}</TableCell>
                  <TableCell align={'left'}>{t_i18n('Full width')}</TableCell>
                  <TableCell align={'center'}>{t_i18n('Order')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {
            threatActorIndividualOverviewLayoutCustomizationWithLabels.map(({ key, label }) => {
              const entry = Object.entries(values).find(([objectKey]) => objectKey === `${key}_isFullWidth`);
              const currentIsFullWidth = entry?.[1];

              return (
                <TableRow
                  key={key}
                  sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                >
                  <TableCell component={'th'} scope={'row'}>{label}</TableCell>
                  <TableCell align={'left'}>
                    <Switch
                      name={`${key}_isFullWidth`}
                      value={currentIsFullWidth}
                      checked={!!currentIsFullWidth}
                      onChange={
                        async (_: React.ChangeEvent, value) => {
                          await setFieldValue(`${key}_isFullWidth`, value);
                          handleSubmitIsFullWidthField(values);
                        }
                      }
                    />
                  </TableCell>
                  <TableCell align={'center'}>
                    <Field sx={{ border: 0 }}
                      component={TextField}
                      name={`${key}_order`}
                      onSubmit={
                        async (field: string, value: number) => {
                          await setFieldValue(field, value);
                          handleSubmitOrderField(values);
                        }
                      }
                    />
                  </TableCell>
                </TableRow>
              );
            })
          }
              </TableBody>
            </Table>
          </TableContainer>
        </Form>
      )}
    </Formik>
  );
};

export default EntitySettingsOverviewLayoutCustomization;
