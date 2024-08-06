import React from 'react';
import { graphql } from 'react-relay';
import { DragDropContext, Droppable, Draggable } from 'react-beautiful-dnd';
import TableContainer from '@mui/material/TableContainer';
import Table from '@mui/material/Table';
import Paper from '@mui/material/Paper';
import TableHead from '@mui/material/TableHead';
import TableCell from '@mui/material/TableCell';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import Switch from '@mui/material/Switch';
import DragIndicatorOutlinedIcon from '@mui/icons-material/DragIndicatorOutlined';
import { Form, Formik } from 'formik';
import { EntitySettingSettings_entitySetting$data } from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingSettings_entitySetting.graphql';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { Theme } from '../../../../../components/Theme';
import { useTheme } from '@mui/styles';

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
      ...EntitySettingsOverviewLayoutCustomization_entitySetting
    }
  }
`;

// removing null | undefined in our generated types
type NonNullableFields<T> = {
  [P in keyof T]: NonNullable<T[P]>;
};
export type EntitySettingsOverviewLayoutCustomizationData = NonNullableFields<Pick<EntitySettingSettings_entitySetting$data, 'id' | 'overview_layout_customization'>>;

interface EntitySettingsOverviewLayoutCustomizationProps {
  entitySettingsData: EntitySettingsOverviewLayoutCustomizationData
}

const EntitySettingsOverviewLayoutCustomization: React.FC<EntitySettingsOverviewLayoutCustomizationProps> = ({
  entitySettingsData: { id, overview_layout_customization },
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const initialValues = {
    ...overview_layout_customization.reduce((accumulator, widgetConfiguration, currentIndex) => ({
      ...accumulator,
      [`${widgetConfiguration.key}_isFullWidth`]: widgetConfiguration.width === 12,
      [`${widgetConfiguration.key}_order`]: currentIndex,
    }), {}),
  };

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

  const onDragEndHandler = (values, { draggableId, source, destination }) => {
    // dropped outside the list
    if (!destination) {
      return;
    }
    const inOrderValues = {};
    if (destination.index > source.index) {
      for (let i = source.index + 1; i <= destination.index; i += 1) {
        inOrderValues[`${overview_layout_customization?.[i]?.key}_order`] = i - 1;
      }
    } else {
      for (let i = destination.index; i <= source.index; i += 1) {
        inOrderValues[`${overview_layout_customization?.[i]?.key}_order`] = i + 1;
      }
    }
    inOrderValues[draggableId] = destination.index;
    console.log("Here ?", { ...values, ...inOrderValues });
    updateLayout({ ...values, ...inOrderValues });
  };

  if (!overview_layout_customization) {
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
      }) => (
        <Form>
          {/* WARN: adding a TableContainer will cause issues with drag and drop lib */}
          {/* <TableContainer component={Paper} sx={{ background: 'none' }}> */}
          <Table
            size="small"
            aria-label={t_i18n('Overview layout customization configuration table')}
          >
            <TableHead>
              <TableRow>
                <TableCell>{t_i18n('Order')}</TableCell>
                <TableCell>{t_i18n('Widget')}</TableCell>
                <TableCell align={'left'}>{t_i18n('Full width')}</TableCell>
              </TableRow>
            </TableHead>
            <DragDropContext onDragEnd={(props) => onDragEndHandler(values, props)}>
              <Droppable droppableId="custom_overview_droppable">
                {(providedDrop) => (
                  <TableBody
                    ref={providedDrop.innerRef}
                    {...providedDrop.droppableProps}
                  >
                    {
                        overview_layout_customization.map(({ key, label }, index) => (
                          <Draggable key={key} draggableId={`${key}_order`} index={index}>
                            {(providedDrag, snapshotDrag) => (
                              <TableRow
                                key={key}
                                ref={providedDrag.innerRef}
                                sx={{
                                  '&:last-child td, &:last-child th': { border: 0 },
                                  background: snapshotDrag.isDragging ? theme.palette.background.accent : theme.palette.background.paper,
                                }}
                                {...providedDrag.draggableProps}
                              >
                                <TableCell
                                  component={'th'}
                                  scope={'row'}
                                  {...providedDrag.dragHandleProps}
                                >
                                  <DragIndicatorOutlinedIcon />
                                </TableCell>
                                <TableCell>
                                  {t_i18n(label)}
                                </TableCell>
                                <TableCell>
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
                              </TableRow>
                            )}
                          </Draggable>
                        ))
                      }
                    {providedDrop.placeholder}
                  </TableBody>
                )}
              </Droppable>
            </DragDropContext>
          </Table>
        </Form>
      )}
    </Formik>
  );
};

export default EntitySettingsOverviewLayoutCustomization;
