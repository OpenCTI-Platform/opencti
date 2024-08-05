import React from 'react';
import { graphql } from 'react-relay';
import TableContainer from '@mui/material/TableContainer';
import Table from '@mui/material/Table';
import Paper from '@mui/material/Paper';
import TableHead from '@mui/material/TableHead';
import TableCell from '@mui/material/TableCell';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import Switch from '@mui/material/Switch';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';

export const entitySettingsOverviewLayoutCustomizationFragment = graphql`
  fragment EntitySettingsOverviewLayoutCustomization_entitySetting on EntitySetting {
    id
    target_type
    overview_layout_customization {
      key
      width
      label
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
  entitySettingsData: { id, overview_layout_customization },
}: {
  entitySettingsData: {
    readonly id: string;
    readonly overview_layout_customization: ReadonlyArray<{
      readonly key: string;
      readonly label: string;
      readonly width: number;
    }>
  },
}) => {
  const { t_i18n } = useFormatter();

  const initialValues = {
    ...overview_layout_customization.reduce((accumulator, widgetConfiguration, currentIndex) => ({
      ...accumulator,
      [`${widgetConfiguration.key}_isFullWidth`]: widgetConfiguration.width === 12,
      [`${widgetConfiguration.key}_order`]: currentIndex + 1,
    }), {}),
  };
  const formValidationSchema = Yup.object().shape({
    ...overview_layout_customization.reduce((accumulator, widgetConfiguration, currentIndex, array) => ({
      ...accumulator,
      [`${widgetConfiguration.key}_isFullWidth`]: Yup.boolean(),
      [`${widgetConfiguration.key}_order`]: Yup.number()
        .min(1, t_i18n('This field must be >= 1'))
        .max(array.length, t_i18n('', { id: 'This field must be <= value', values: { value: array.length } })),
    }), {}),
  });

  const [commitUpdate] = useApiMutation((entitySettingsOverviewLayoutCustomizationEdit));
  const editInputsKeys = overview_layout_customization.map(({ key }) => key);
  const editLabels: Record<string, string> = overview_layout_customization.reduce((o, { key, label }) => ({ ...o, [key]: label }), {});
  const updateLayout = (values: Record<string, boolean | number>) => {
    const input = {
      key: 'overview_layout_customization',
      value: editInputsKeys.map((inputKey) => ({
        key: inputKey,
        width: (values[`${inputKey}_isFullWidth`] as boolean) ? 12 : 6,
        order: (values[`${inputKey}_order`] as number),
        label: editLabels[inputKey],
      })),
    };
    commitUpdate({
      variables: {
        ids: [id],
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

  if (!overview_layout_customization) {
    return null;
  }

  return (
    <Formik<typeof initialValues>
      enableReinitialize={true}
      initialValues={initialValues}
      onSubmit={() => {}}
      validationSchema={formValidationSchema}
    >
      {({
        values,
        setFieldValue,
      }) => (
        <Form>
          <TableContainer component={Paper} sx={{ background: 'none' }}>
            <Table size="small" aria-label={t_i18n('Overview layout customization configuration table')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Widget')}</TableCell>
                  <TableCell align={'left'}>{t_i18n('Full width')}</TableCell>
                  <TableCell align={'center'}>{t_i18n('Order')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {
                  overview_layout_customization.map(({ key, label }) => {
                    return (
                      <TableRow
                        key={key}
                        sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                      >
                        <TableCell component={'th'} scope={'row'}>{t_i18n(label)}</TableCell>
                        <TableCell align={'left'}>
                          <Switch
                            name={`${key}_isFullWidth`}
                            checked={((values as Record<string, boolean>)[`${key}_isFullWidth`])}
                            onChange={
                              async (_: unknown, value) => {
                                handleSubmitIsFullWidthField({ ...values, [`${key}_isFullWidth`]: value });
                              }
                            }
                          />
                        </TableCell>
                        <TableCell align={'center'}>
                          <Field
                            sx={{ border: 0 }}
                            component={TextField}
                            type="number"
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
