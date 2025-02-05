import { Drawer, SxProps, Toolbar, Alert } from '@mui/material';
import React, { FunctionComponent, useMemo, useState } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { useFintelTemplateContext } from '@components/settings/sub_types/fintel_templates/FintelTemplateContext';
import { useParams } from 'react-router-dom';
import useFintelTemplateEdit from './useFintelTemplateEdit';
import { FintelTemplateWidgetsSidebar_template$key } from './__generated__/FintelTemplateWidgetsSidebar_template.graphql';
import FintelTemplateWidgetsList, { FintelTemplateWidget } from './FintelTemplateWidgetsList';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { MESSAGING$ } from '../../../../../relay/environment';
import WidgetConfig from '../../../widgets/WidgetConfig';
import type { Widget } from '../../../../../utils/widget/widget';
import { deserializeFilterGroupForFrontend, emptyFilterGroup, removeIdFromFilterGroupObject } from '../../../../../utils/filters/filtersUtils';
import DeleteDialog from '../../../../../components/DeleteDialog';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import { toCamelCase } from '../../../../../utils/String';

export const FINTEL_TEMPLATE_SIDEBAR_WIDTH = 350;

const sidebarFragment = graphql`
  fragment FintelTemplateWidgetsSidebar_template on FintelTemplate {
    id
    fintel_template_widgets {
      variable_name
      widget {
        id
        type
        perspective
        dataSelection {
          label
          number
          attribute
          date_attribute
          centerLat
          centerLng
          zoom
          isTo
          perspective
          filters
          dynamicTo
          dynamicFrom
          instance_id
          sort_by
          sort_mode
          columns {
            variableName
            label
            attribute
          }
        }
        parameters {
          title
          interval
          stacked
          legend
          distributed
        }
      }
    }
  }
`;

interface FintelTemplateWidetsSidebarProps {
  data: FintelTemplateWidgetsSidebar_template$key,
}

const FintelTemplateWidgetsSidebar: FunctionComponent<FintelTemplateWidetsSidebarProps> = ({ data }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { editorValue } = useFintelTemplateContext();
  const { subTypeId } = useParams<{ subTypeId?: string }>();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const { id, fintel_template_widgets } = useFragment(sidebarFragment, data);

  const [commitEditMutation] = useFintelTemplateEdit();
  const deletion = useDeletion({});
  const { handleCloseDelete, handleOpenDelete } = deletion;

  const [isWidgetFormOpen, setIsWidgetFormOpen] = useState(false);
  const [selectedWidget, setSelectedWidget] = useState<FintelTemplateWidget>();

  const isSelectedWidgetUsed = selectedWidget && !!editorValue?.includes(`$${selectedWidget.variable_name}`);

  const selectedWidgetIndex = useMemo(() => {
    return fintel_template_widgets.findIndex((w) => w.variable_name === selectedWidget?.variable_name);
  }, [fintel_template_widgets, selectedWidget]);

  const formattedFintelTemplateWidgets: FintelTemplateWidget[] = fintel_template_widgets
    .map((template) => ({
      ...template,
      widget: {
        ...template.widget,
        dataSelection: template.widget.dataSelection.map((selection) => ({
          ...selection,
          filters: selection.filters ? deserializeFilterGroupForFrontend(selection.filters) : emptyFilterGroup,
          dynamicFrom: selection.dynamicFrom ? deserializeFilterGroupForFrontend(selection.dynamicFrom) : emptyFilterGroup,
          dynamicTo: selection.dynamicTo ? deserializeFilterGroupForFrontend(selection.dynamicTo) : emptyFilterGroup,
        })),
      },
    }) as FintelTemplateWidget);

  const onOpenUpdate = (widget: FintelTemplateWidget) => {
    setSelectedWidget(widget);
    setIsWidgetFormOpen(true);
  };

  const onOpenDelete = (widget: FintelTemplateWidget) => {
    setSelectedWidget(widget);
    handleOpenDelete();
  };

  const handleWidgetConfigOpen = (isOpen: boolean) => {
    setIsWidgetFormOpen(isOpen);
    if (!isOpen) {
      setSelectedWidget(undefined);
    }
  };

  const closeDeleteConfirm = () => {
    handleCloseDelete();
    setSelectedWidget(undefined);
  };

  const submitDeleteWidget = () => {
    if (selectedWidgetIndex < 0) {
      throw Error('Selected widget index should be positive.');
    }
    commitEditMutation({
      variables: {
        id,
        input: [{
          key: 'fintel_template_widgets',
          object_path: `fintel_template_widgets/${selectedWidgetIndex}`,
          value: [null],
          operation: 'remove',
        }],
      },
      onError: closeDeleteConfirm,
      onCompleted: closeDeleteConfirm,
    });
  };

  const checkWidgetIsValid = (widget: Widget, variableName?: string) => {
    if (widget.type === 'attribute') {
      const selectionsCheck = widget.dataSelection.map((selection) => selection.columns?.every((c) => c.variableName));
      return !!selectionsCheck.every((c) => c);
    }
    // variableName is added for attribute widget
    if (!variableName) {
      MESSAGING$.notifyError(t_i18n('You should provide a variable name'));
      return false;
    } if (variableName.includes(' ')) {
      MESSAGING$.notifyError(t_i18n('The variable name should not contain spaces'));
      return false;
    } if (!variableName.match(/^[A-Za-z0-9_-]+$/)) {
      MESSAGING$.notifyError(t_i18n('The variable name should not contain special characters'));
      return false;
    }
    return true;
  };

  const handleUpsertWidget = (widget: Widget, variableName?: string) => {
    const isWidgetValid = checkWidgetIsValid(widget, variableName);
    if (isWidgetValid) {
      // build fintel template widget with variable name and stringified filters
      const fintelTemplateWidget = {
        variable_name: widget.type === 'attribute' && widget.parameters?.title
          ? toCamelCase(widget.parameters.title) // set a variable name from the title for attribute widgets
          : variableName,
        widget: {
          ...widget,
          dataSelection: widget.dataSelection.map((selection) => ({
            ...selection,
            filters: JSON.stringify(removeIdFromFilterGroupObject(selection.filters)),
            dynamicFrom: JSON.stringify(removeIdFromFilterGroupObject(selection.dynamicFrom)),
            dynamicTo: JSON.stringify(removeIdFromFilterGroupObject(selection.dynamicTo)),
          })),
        },
      };
      if (!selectedWidget) { // case widget creation
        commitEditMutation({
          variables: {
            id,
            // add the widget in the fintel template widgets list
            input: [{
              key: 'fintel_template_widgets',
              value: [fintelTemplateWidget],
              operation: 'add',
            }],
          },
        });
      } else { // case widget update
        if (selectedWidgetIndex < 0) {
          throw Error('Selected widget index should be positive.');
        }
        commitEditMutation({
          variables: {
            id,
            // update the widget in the fintel template widgets list
            input: [{
              key: 'fintel_template_widgets',
              object_path: `fintel_template_widgets/${selectedWidgetIndex}`,
              value: [fintelTemplateWidget],
            }],
          },
        });
      }
    }
  };

  const paperStyle: SxProps = {
    '.MuiDrawer-paper': {
      width: FINTEL_TEMPLATE_SIDEBAR_WIDTH,
      padding: `${theme.spacing(2)} 0`,
      paddingTop: `calc(${theme.spacing(2)} +  ${settingsMessagesBannerHeight}px)`,
    },
  };

  return (
    <>
      <Drawer variant="permanent" anchor="right" sx={paperStyle}>
        <Toolbar />

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <FintelTemplateWidgetsList
            onCreateWidget={() => setIsWidgetFormOpen(true)}
            widgets={formattedFintelTemplateWidgets}
            onUpdateWidget={onOpenUpdate}
            onDeleteWidget={onOpenDelete}
          />
        </div>
      </Drawer>

      <WidgetConfig
        open={isWidgetFormOpen}
        setOpen={handleWidgetConfigOpen}
        onComplete={handleUpsertWidget}
        widget={selectedWidget?.widget}
        disabledSteps={[0]}
        context="fintelTemplate"
        fintelWidgets={fintel_template_widgets as FintelTemplateWidget[]}
        fintelEntityType={subTypeId}
        fintelEditorValue={editorValue ?? ''}
        initialVariableName={selectedWidget?.variable_name}
      />

      <DeleteDialog
        title={(
          <>
            <span>{t_i18n('Are you sure you want to delete this widget?')}</span>
            {isSelectedWidgetUsed && (
              <Alert severity="warning" variant="outlined" sx={{ marginTop: 2 }}>
                {t_i18n('You are about to delete a widget used in the template')}
              </Alert>
            )}
          </>
        )}
        deletion={deletion}
        submitDelete={submitDeleteWidget}
      />
    </>
  );
};

export default FintelTemplateWidgetsSidebar;
