import React, { FunctionComponent } from 'react';
import { DragDropContext, Draggable, Droppable } from '@hello-pangea/dnd';
import { Box, Checkbox, FormControlLabel, IconButton, List, ListItem, ListItemIcon, ListItemText, Radio, RadioGroup, Typography } from '@mui/material';
import AccordionDetails from '@mui/material/AccordionDetails';
import { Close, DragIndicatorOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import type { WidgetColumn } from '../../../utils/widget/widget';
import { Accordion, AccordionSummary } from '../../../components/Accordion';
import useWidgetColumnsCustomization from './useWidgetColumnsCustomization';

export type WidgetColumnsLayout = '1' | '2';

type WidgetCustomAttributesColumnsInputProps = {
  availableColumns: WidgetColumn[];
  defaultColumns: WidgetColumn[];
  value?: WidgetColumn[];
  onChange: (columns: WidgetColumn[]) => void;
  layout?: WidgetColumnsLayout;
  onLayoutChange?: (layout: WidgetColumnsLayout) => void;
};

type DraggableColumnItemProps = {
  column: WidgetColumn;
  index: number;
  isLast: boolean;
  label: string;
  onRemove: (attribute?: string | null) => void;
};

const DraggableColumnItem: FunctionComponent<DraggableColumnItemProps> = ({
  column,
  index,
  isLast,
  label,
  onRemove,
}) => (
  <Draggable key={column.attribute} draggableId={column.attribute ?? ''} index={index}>
    {(providedDrag, snapshotDrag) => (
      <ListItem
        ref={providedDrag.innerRef}
        {...providedDrag.draggableProps}
        divider={!isLast}
        sx={{
          ...providedDrag.draggableProps.style,
          background: snapshotDrag.isDragging ? 'rgba(0, 0, 0, 0.05)' : 'inherit',
          height: 42,
        }}
        secondaryAction={(
          <IconButton onClick={() => onRemove(column.attribute)}>
            <Close />
          </IconButton>
        )}
      >
        <ListItemIcon {...providedDrag.dragHandleProps}>
          <DragIndicatorOutlined />
        </ListItemIcon>
        <ListItemText primary={label} />
      </ListItem>
    )}
  </Draggable>
);

const WidgetCustomAttributesColumnsInput: FunctionComponent<WidgetCustomAttributesColumnsInputProps> = ({
  availableColumns,
  defaultColumns,
  value = [],
  onChange,
  layout = '1',
  onLayoutChange,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const { handleDragEndSingleColumn, handleDragEndDoubleColumns, handleToggleColumn, formatColumnName } = useWidgetColumnsCustomization(
    availableColumns,
    value,
    onChange,
  );

  const col1Items = value.filter((_, i) => i % 2 === 0);
  const col2Items = value.filter((_, i) => i % 2 === 1);

  const listSx = {
    border: `1px solid ${theme.palette.common.white}`,
    borderRadius: `${theme.borderRadius}px`,
    paddingBlock: theme.spacing(1),
  };

  return (
    <Accordion sx={{ width: '100%' }} defaultExpanded>
      <AccordionSummary>
        <Typography>{t_i18n('Customize attributes')}</Typography>
      </AccordionSummary>
      <AccordionDetails sx={{ background: 'none', paddingBlock: theme.spacing(2) }}>

        {/* Layout selector */}
        {onLayoutChange && (
          <Box sx={{ marginBottom: theme.spacing(2) }}>
            <Typography variant="h4">{t_i18n('Layout')}</Typography>
            <RadioGroup
              row
              value={layout}
              onChange={(e) => onLayoutChange(e.target.value as WidgetColumnsLayout)}
            >
              <FormControlLabel value="1" control={<Radio size="small" />} label={t_i18n('1 column')} />
              <FormControlLabel value="2" control={<Radio size="small" />} label={t_i18n('2 columns')} />
            </RadioGroup>
          </Box>
        )}

        <Box sx={{ display: 'flex', width: '100%', gap: theme.spacing(2) }}>
          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <Typography variant="h4">
              {`${t_i18n('Available attributes')} (${availableColumns.length})`}
            </Typography>
            <List sx={{ ...listSx, flex: 1 }}>
              {availableColumns.map((column) => (
                <ListItem disablePadding key={column.attribute} sx={{ height: 42 }}>
                  <Checkbox
                    checked={value.some((col) => col.attribute === column.attribute)}
                    onChange={() => handleToggleColumn(column.attribute)}
                  />
                  <ListItemText primary={t_i18n(formatColumnName(column))} />
                </ListItem>
              ))}
            </List>
          </Box>

          {/* Selected — 2/3, layout 1 or 2 columns */}
          <DragDropContext onDragEnd={layout === '2' ? handleDragEndDoubleColumns : handleDragEndSingleColumn}>
            {layout === '2' ? (
              <Box sx={{
                flex: 2,
                display: 'flex',
                flexDirection: 'column',
              }}
              >
                <Typography variant="h4">
                  {`${t_i18n('Selected attributes')} (${value.length})`}
                </Typography>
                <Box sx={{
                  display: 'flex',
                  flex: 1,
                  border: `1px solid ${theme.palette.common.white}`,
                  borderRadius: `${theme.borderRadius}px`,
                  overflow: 'hidden',
                }}
                >
                  {(['col_1', 'col_2'] as const).map((colId, colIndex) => {
                    const colItems = colIndex === 0 ? col1Items : col2Items;
                    return (
                      <Droppable key={colId} droppableId={colId}>
                        {(providedDrop) => (
                          <Box
                            ref={providedDrop.innerRef}
                            {...providedDrop.droppableProps}
                            sx={{
                              flex: 1,
                              paddingTop: theme.spacing(1),
                              minHeight: 100,
                            }}
                          >
                            {colItems.map((column, index) => (
                              <DraggableColumnItem
                                key={column.attribute}
                                column={column}
                                index={index}
                                isLast={index === colItems.length - 1}
                                label={t_i18n(formatColumnName(column))}
                                onRemove={handleToggleColumn}
                              />
                            ))}
                            {providedDrop.placeholder}
                          </Box>
                        )}
                      </Droppable>
                    );
                  })}
                </Box>
              </Box>
            ) : (
              <Box sx={{ flex: 2 }}>
                <Typography variant="h4">
                  {`${t_i18n('Selected attributes')} (${value.length})`}
                </Typography>
                <Droppable droppableId="col_1">
                  {(providedDrop) => (
                    <List
                      ref={providedDrop.innerRef}
                      {...providedDrop.droppableProps}
                      sx={listSx}
                    >
                      {value.map((column, index) => (
                        <DraggableColumnItem
                          key={column.attribute}
                          column={column}
                          index={index}
                          isLast={index === value.length - 1}
                          label={t_i18n(formatColumnName(column))}
                          onRemove={handleToggleColumn}
                        />
                      ))}
                      {providedDrop.placeholder}
                    </List>
                  )}
                </Droppable>
              </Box>
            )}
          </DragDropContext>
        </Box>

        <Box sx={{ display: 'flex', marginTop: 2, justifyContent: 'flex-end' }}>
          <Button variant="secondary" onClick={() => onChange(defaultColumns)}>
            {t_i18n('Reset')}
          </Button>
        </Box>

      </AccordionDetails>
    </Accordion>
  );
};

export default WidgetCustomAttributesColumnsInput;
