import React from 'react';
import { graphql } from 'react-relay';
import { DragDropContext, Draggable, Droppable, DropResult } from '@hello-pangea/dnd';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableCell from '@mui/material/TableCell';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import { Switch, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { DragIndicatorOutlined } from '@mui/icons-material';
import { Form, Formik } from 'formik';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../../relay/environment';
import { HIDDEN_OVERVIEW_WIDGET_WIDTH } from '../../../../../utils/hooks/useOverviewLayoutCustomization';
import type { Theme } from '../../../../../components/Theme';
import type { EntitySettingsOverviewLayoutCustomization_entitySetting$data } from './__generated__/EntitySettingsOverviewLayoutCustomization_entitySetting.graphql';

export const entitySettingsOverviewLayoutCustomizationFragment = graphql`
  fragment EntitySettingsOverviewLayoutCustomization_entitySetting on EntitySetting {
    id
    target_type
    overview_layout_customization {
      key
      width
      label
    }
    defaultOverviewLayoutCustomization {
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
      ...EntitySettingsOverviewLayoutCustomization_entitySetting
    }
  }
`;

// removing null | undefined in our generated types
type NonNullableFields<T> = {
  [P in keyof T]: NonNullable<T[P]>;
};
type LayoutCustomizationData = EntitySettingsOverviewLayoutCustomization_entitySetting$data;
export type EntitySettingsOverviewLayoutCustomizationData = NonNullableFields<Pick<LayoutCustomizationData, 'id' | 'overview_layout_customization'>>
  & Partial<Pick<LayoutCustomizationData, 'defaultOverviewLayoutCustomization'>>;

interface EntitySettingsOverviewLayoutCustomizationProps {
  entitySettingsData: EntitySettingsOverviewLayoutCustomizationData;
}

const EntitySettingsOverviewLayoutCustomization: React.FC<EntitySettingsOverviewLayoutCustomizationProps> = ({
  entitySettingsData: { id, overview_layout_customization, defaultOverviewLayoutCustomization },
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [commitUpdate, updateInFlight] = useApiMutation(entitySettingsOverviewLayoutCustomizationEdit);

  if (!overview_layout_customization) {
    return null;
  }

  const getFormValuesFromData = (data: typeof overview_layout_customization) => {
    return {
      ...data.reduce((accumulator, widgetConfiguration, currentIndex) => ({
        ...accumulator,
        [`${widgetConfiguration.key}_isDisplayed`]: widgetConfiguration.width !== HIDDEN_OVERVIEW_WIDGET_WIDTH,
        [`${widgetConfiguration.key}_isFullWidth`]: widgetConfiguration.width === 12,
        [`${widgetConfiguration.key}_order`]: currentIndex,
      }), {}),
    };
  };

  const initialValues = getFormValuesFromData(overview_layout_customization);

  const editInputsKeys = overview_layout_customization.map(({ key }) => key);
  const editLabels: Record<string, string> = overview_layout_customization.reduce((o, { key, label }) => ({ ...o, [key]: label }), {});
  const defaultWidths: Record<string, number> = Object.fromEntries((defaultOverviewLayoutCustomization ?? []).map(({ key, width }) => [key, width]));
  const getWidth = (values: Record<string, boolean | number>, inputKey: string) => {
    if (!values[`${inputKey}_isDisplayed`]) {
      return HIDDEN_OVERVIEW_WIDGET_WIDTH;
    }
    return values[`${inputKey}_isFullWidth`] ? 12 : 6;
  };
  const updateLayout = (values: Record<string, boolean | number>) => {
    const input = {
      key: 'overview_layout_customization',
      value: editInputsKeys
        .sort((keyA, keyB) => (values[`${keyA}_order`] as number) - (values[`${keyB}_order`] as number))
        .map((inputKey) => ({
          key: inputKey,
          width: getWidth(values, inputKey),
          label: editLabels[inputKey],
        })),
    };
    commitUpdate({
      variables: {
        ids: [id],
        input,
      },
      // A refused change (rights, validation) comes back as payload errors: the switches keep the stored layout and the
      // administrator is told why
      onCompleted: (_, errors) => {
        if (errors && errors.length > 0) MESSAGING$.notifyError(errors.map((error) => error.message).join('\n'));
      },
    });
  };

  const onDragEndHandler = (values: typeof initialValues, { draggableId, source, destination }: DropResult) => {
    // dropped outside the list
    if (!destination) {
      return;
    }
    const inOrderValues: Record<string, number> = {};
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
    updateLayout({ ...values, ...inOrderValues });
  };

  return (
    <Formik<typeof initialValues>
      enableReinitialize={true}
      initialValues={initialValues}
      onSubmit={() => {}}
    >
      {({ values }) => (
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
                <TableCell align="left">{t_i18n('Displayed')}</TableCell>
                <TableCell align="left">{t_i18n('Full width')}</TableCell>
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
                      overview_layout_customization.map(({ key, label }, index) => {
                        const isDisplayed = (values as Record<string, boolean>)[`${key}_isDisplayed`];
                        const widget = t_i18n(label);
                        const fullWidthSwitch = (
                          <Switch
                            name={`${key}_isFullWidth`}
                            checked={isDisplayed && (values as Record<string, boolean>)[`${key}_isFullWidth`]}
                            onCheckedChange={(checked: boolean) => updateLayout({ ...values, [`${key}_isFullWidth`]: checked })}
                            disabled={updateInFlight || !isDisplayed}
                            aria-label={t_i18n('Show {widget} at full width', { values: { widget } })}
                          />
                        );
                        return (
                          <Draggable key={key} draggableId={`${key}_order`} index={index} isDragDisabled={updateInFlight}>
                            {(providedDrag, snapshotDrag) => (
                              <TableRow
                                key={key}
                                ref={providedDrag.innerRef}
                                data-testid={`overview-layout-widget-${key}`}
                                sx={{
                                  '& td, & th': { borderColor: 'border.lightBackground' },
                                  background: snapshotDrag.isDragging ? theme.palette.background.accent : undefined,
                                }}
                                {...providedDrag.draggableProps}
                              >
                                <TableCell
                                  component="th"
                                  scope="row"
                                  style={{
                                    verticalAlign: 'bottom',
                                  }}
                                  {...providedDrag.dragHandleProps}
                                >
                                  <DragIndicatorOutlined />
                                </TableCell>
                                <TableCell sx={{ color: isDisplayed ? undefined : 'text.secondary' }}>
                                  {widget}
                                </TableCell>
                                <TableCell>
                                  <Switch
                                    name={`${key}_isDisplayed`}
                                    checked={isDisplayed}
                                    onCheckedChange={(checked: boolean) => updateLayout({
                                      ...values,
                                      [`${key}_isDisplayed`]: checked,
                                      ...(checked ? { [`${key}_isFullWidth`]: (defaultWidths[key] ?? 6) === 12 } : {}),
                                    })}
                                    disabled={updateInFlight}
                                    aria-label={t_i18n('Display {widget}', { values: { widget } })}
                                  />
                                </TableCell>
                                <TableCell>
                                  {isDisplayed ? fullWidthSwitch : (
                                    <Tooltip>
                                      <TooltipTrigger asChild>
                                        <span tabIndex={0} style={{ display: 'inline-flex' }}>{fullWidthSwitch}</span>
                                      </TooltipTrigger>
                                      <TooltipContent>{t_i18n('Display the widget to choose its width')}</TooltipContent>
                                    </Tooltip>
                                  )}
                                </TableCell>
                              </TableRow>
                            )}
                          </Draggable>
                        );
                      })
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
