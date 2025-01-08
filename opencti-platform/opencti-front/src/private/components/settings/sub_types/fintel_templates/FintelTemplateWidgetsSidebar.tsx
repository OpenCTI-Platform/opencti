import { Drawer, SxProps, Toolbar, MenuItem, Menu } from '@mui/material';
import React, { FunctionComponent, MouseEvent, useState } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { FintelTemplateWidgetsSidebar_template$key } from './__generated__/FintelTemplateWidgetsSidebar_template.graphql';
import FintelTemplateWidgetsList, { FintelTemplateWidget } from './FintelTemplateWidgetsList';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { MESSAGING$ } from '../../../../../relay/environment';
import WidgetConfig from '../../../widgets/WidgetConfig';
import type { Widget } from '../../../../../utils/widget/widget';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { emptyFilterGroup, removeIdFromFilterGroupObject } from '../../../../../utils/filters/filtersUtils';
import DeleteDialog from '../../../../../components/DeleteDialog';
import useDeletion from '../../../../../utils/hooks/useDeletion';

export const FINTEL_TEMPLATE_SIDEBAR_WIDTH = 350;

export const widgetsFragment = graphql`
  fragment FintelTemplateWidgetsSidebar_template on FintelTemplate {
    id
    template_content
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
        layout {
          w
          h
          x
          y
          i
          moved
          static
        }
      }
    }
  }
`;

export const fintelTemplateWidgetMutationFieldPatch = graphql`
  mutation FintelTemplateWidgetsSidebarWidgetsFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    fintelTemplateFieldPatch(id: $id, input: $input) {
      ...FintelTemplateWidgetsSidebar_template
    }
  }
`;

interface FintelTemplateWidetsSidebarProps {
  data: FintelTemplateWidgetsSidebar_template$key,
}

const FintelTemplateWidgetsSidebar: FunctionComponent<FintelTemplateWidetsSidebarProps> = ({ data }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const { id, template_content, fintel_template_widgets: fintelTemplateWidgets } = useFragment(widgetsFragment, data);

  const formattedFintelTemplateWidgets: FintelTemplateWidget[] = fintelTemplateWidgets
    .map((template) => ({
      ...template,
      widget: {
        ...template.widget,
        dataSelection: template.widget.dataSelection.map((selection) => ({
          ...selection,
          filters: selection.filters ? JSON.parse(selection.filters) : emptyFilterGroup,
          dynamicFrom: selection.dynamicFrom ? JSON.parse(selection.dynamicFrom) : emptyFilterGroup,
          dynamicTo: selection.dynamicTo ? JSON.parse(selection.dynamicTo) : emptyFilterGroup,
        })),
      },
    }) as FintelTemplateWidget);

  const formattedFintelTemplateWidgetsForList = formattedFintelTemplateWidgets
    .map((template) => (template.widget.type === 'attribute'
      ? (template.widget.dataSelection[0].columns ?? []).map((c) => ({
        id: template.widget.id,
        variableName: c.variableName,
        type: template.widget.type,
      }))
      : {
        id: template.widget.id,
        variableName: template.variable_name,
        type: template.widget.type,
      }))
    .flat() as { id: string, variableName: string, type: string }[];

  const usedWidgets = formattedFintelTemplateWidgetsForList.filter((w) => template_content.includes(`$${w.variableName}`));

  const [selectedVariable, setSelectedVariable] = useState<string | undefined>(undefined);
  const [isWidgetFormOpen, setIsWidgetFormOpen] = useState<boolean>(false);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);

  const [commitWidgetUpdate] = useApiMutation(fintelTemplateWidgetMutationFieldPatch);
  const deletion = useDeletion({});
  const { handleCloseDelete, handleOpenDelete } = deletion;

  const selectedWidget = formattedFintelTemplateWidgets.find((t) => t.variable_name === selectedVariable)?.widget as Widget ?? undefined;
  const selectedWidgetIndex = formattedFintelTemplateWidgets.map((t) => t.variable_name).indexOf(selectedVariable ?? '');

  const paperStyle: SxProps = {
    '.MuiDrawer-paper': {
      width: FINTEL_TEMPLATE_SIDEBAR_WIDTH,
      padding: `${theme.spacing(2)} 0`,
      paddingTop: `calc(${theme.spacing(2)} +  ${settingsMessagesBannerHeight}px)`,
    },
  };

  const handleOpenPopover = (event: MouseEvent<HTMLButtonElement>, variable: string) => {
    setAnchorEl(event.currentTarget);
    setSelectedVariable(variable);
  };

  const handleOpenUpdate = () => {
    setIsWidgetFormOpen(true);
  };

  const handleWidgetConfigOpen = (isOpen: boolean) => {
    setIsWidgetFormOpen(isOpen);
    if (!isOpen) {
      setAnchorEl(null);
      setSelectedVariable(undefined);
    }
  };

  const handleClosePopover = () => {
    handleWidgetConfigOpen(false);
  };

  const onOpenDelete = () => {
    handleOpenDelete();
    setAnchorEl(null);
  };

  const handleDeleteWidget = () => {
    if (selectedWidgetIndex < 0) {
      throw Error('Selected widget index should be positive.');
    }
    const editInput = {
      key: 'fintel_template_widgets',
      object_path: `fintel_template_widgets/${selectedWidgetIndex}`,
      value: [null],
      operation: 'remove',
    };
    commitWidgetUpdate({
      variables: {
        id,
        input: editInput,
      },
      onCompleted: () => {
        handleCloseDelete();
        setSelectedVariable(undefined);
      },
    });
  };

  const handleUpsertWidget = (widget: Widget, variableName?: string) => {
    if (!variableName) {
      MESSAGING$.notifyError(t_i18n('You should provide a variable name'));
    } else if (variableName.includes(' ')) {
      MESSAGING$.notifyError(t_i18n('The variable name should not contain blanks'));
    }
    // build fintel template widget with variable name and stringified filters
    const fintelTemplateWidget = {
      variable_name: variableName,
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
      // add the widget in the fintel template widgets list
      const editInput = {
        key: 'fintel_template_widgets',
        value: [fintelTemplateWidget],
        operation: 'add',
      };
      commitWidgetUpdate({
        variables: {
          id,
          input: editInput,
        },
      });
    } else { // case widget update
      // update the widget in the fintel template widgets list
      const editInput = {
        key: 'fintel_template_widgets',
        object_path: `fintel_template_widgets/${selectedWidgetIndex}`,
        value: [fintelTemplateWidget],
      };
      commitWidgetUpdate({
        variables: {
          id,
          input: editInput,
        },
      });
    }
  };

  const handleOpenCreateWidget = () => {
    setIsWidgetFormOpen(true);
  };

  const copyWidgetToClipboard = async () => {
    if (selectedVariable) {
      await navigator.clipboard.writeText(`$${selectedVariable}`);
      MESSAGING$.notifySuccess(t_i18n('Widget copied to clipboard'));
    }
    setAnchorEl(null);
  };

  return (
    <>
      <Drawer variant="permanent" anchor="right" sx={paperStyle}>
        <Toolbar />

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <FintelTemplateWidgetsList
            title={t_i18n('Available template widgets')}
            onCreateWidget={handleOpenCreateWidget}
            widgets={formattedFintelTemplateWidgets}
            handleOpenPopover={handleOpenPopover}
          />
        </div>
      </Drawer>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClosePopover}
      >
        <MenuItem onClick={copyWidgetToClipboard}>
          {t_i18n('Copy widget to clipboard')}
        </MenuItem>
        <MenuItem onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem
          onClick={onOpenDelete}
          disabled={!!usedWidgets.find((w) => w.variableName === selectedVariable)}
        >
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>

      <WidgetConfig
        open={isWidgetFormOpen}
        setOpen={handleWidgetConfigOpen}
        onComplete={handleUpsertWidget}
        context={'fintelTemplate'}
        widget={selectedWidget}
        initialVariableName={selectedVariable}
      />

      <DeleteDialog
        title={t_i18n('Are you sure you want to remove this widget?')}
        deletion={deletion}
        submitDelete={handleDeleteWidget}
      />
    </>
  );
};

export default FintelTemplateWidgetsSidebar;
