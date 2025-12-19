import IconButton from '@common/button/IconButton';
import { AddOutlined, CancelOutlined } from '@mui/icons-material';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import WidgetFilters from '@components/widgets/WidgetFilters';
import Button from '@common/button/Button';
import React, { useState } from 'react';
import { v4 as uuidv4 } from 'uuid';
import { Box, Stack } from '@mui/material';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import type { WidgetPerspective } from '../../../utils/widget/widget';
import { getCurrentCategory, getCurrentDataSelectionLimit, isWidgetUsingRelationsAggregation } from '../../../utils/widget/widgetUtils';
import { useWidgetConfigContext } from './WidgetConfigContext';
import Alert from '../../../components/Alert';

type StepContainerProps = {
  perspective?: WidgetPerspective | null;
  children: React.ReactNode;
};

const StepContainer = ({ perspective, children }: StepContainerProps) => {
  let borderColorKey: 'primary' | 'secondary' = 'secondary';

  if (perspective === 'relationships') {
    borderColorKey = 'primary';
  } else if (perspective === 'audits') {
    borderColorKey = 'secondary';
  }

  return (
    <Box
      sx={{
        position: 'relative',
        width: '100%',
        mb: 2,
        p: 2,
        verticalAlign: 'middle',
        border: (theme) => `1px solid ${theme.palette[borderColorKey].main}`,
        borderRadius: 1,
      }}
    >
      {children}
    </Box>
  );
};

const WidgetCreationDataSelection = () => {
  const { t_i18n } = useFormatter();
  const { config, setStep, setDataSelection, setDataSelectionWithIndex } = useWidgetConfigContext();
  const { type, dataSelection, perspective } = config.widget;

  const [itemIds, setItemIds] = useState<string[]>(() => dataSelection.map(() => uuidv4()));

  const isDataSelectionFiltersValid = () => {
    return dataSelection.length > 0;
  };

  const handleRemoveDataSelection = (i: number) => {
    const newDataSelection = Array.from(dataSelection);
    newDataSelection.splice(i, 1);

    const newItemIds = Array.from(itemIds);
    newItemIds.splice(i, 1);

    setDataSelection(newDataSelection);
    setItemIds(newItemIds);
  };

  const handleChangeDataValidationLabel = (i: number, value: string) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return { ...data, label: value };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };

  const handleAddDataSelection = (subPerspective: WidgetPerspective) => {
    setDataSelection([
      ...dataSelection,
      {
        label: '',
        attribute: 'entity_type',
        date_attribute: 'created_at',
        perspective: subPerspective,
        filters: emptyFilterGroup,
        dynamicFrom: emptyFilterGroup,
        dynamicTo: emptyFilterGroup,
      },
    ]);

    const newId = uuidv4();
    setItemIds([...itemIds, newId]);
  };

  const showRelationCountWarning = type && isWidgetUsingRelationsAggregation(type);

  return (
    <div style={{ marginTop: 20 }}>
      {
        dataSelection.map((item, i) => {
          return (
            <StepContainer
              key={itemIds[i]}
              perspective={item.perspective}
            >
              <IconButton
                disabled={dataSelection.length === 1}
                aria-label="Delete"
                style={{
                  position: 'absolute',
                  top: -20,
                  right: -20,
                }}
                onClick={() => handleRemoveDataSelection(i)}
              >
                <CancelOutlined fontSize="small" />
              </IconButton>

              <Stack direction="row" sx={{ width: '100%' }}>
                <TextField
                  style={{ flex: 1 }}
                  label={`${t_i18n('Label')} (${dataSelection[i].perspective})`}
                  fullWidth={true}
                  value={dataSelection[i].label}
                  onChange={(event) => handleChangeDataValidationLabel(i, event.target.value)}
                />
                {
                  perspective === 'relationships' && (
                    <Tooltip
                      title={t_i18n(
                        'The relationships taken into account are: stix core relationships, sightings and \'contains\' relationships',
                      )}
                    >
                      <InformationOutline
                        fontSize="small"
                        color="primary"
                        style={{ marginRight: 5, marginTop: 20 }}
                      />
                    </Tooltip>
                  )
                }
              </Stack>

              <WidgetFilters
                dataSelection={dataSelection[i]}
                setDataSelection={(data) => setDataSelectionWithIndex(data, i)}
                perspective={dataSelection[i].perspective ?? perspective}
                type={type}
              />
            </StepContainer>
          );
        })
      }

      {perspective === 'entities' && (
        <div style={{ display: 'flex' }}>
          <IconButton
            disabled={getCurrentDataSelectionLimit(type) === dataSelection.length}
            color="secondary"
            size="small"
            onClick={() => handleAddDataSelection('entities')}
            style={{
              width: '100%',
              height: 20,
              flex: 1,
            }}
          >
            <AddOutlined fontSize="small" />
          </IconButton>
        </div>
      )}

      {perspective === 'relationships' && (
        <Stack direction="row">
          <Button
            disabled={getCurrentDataSelectionLimit(type) === dataSelection.length}
            size="small"
            onClick={() => handleAddDataSelection('relationships')}
            style={{
              width: '100%',
              height: 20,
              flex: 1,
              marginRight: 20,
            }}
          >
            <AddOutlined fontSize="small" /> {t_i18n('Relationships')}
          </Button>
          <Button
            disabled={getCurrentDataSelectionLimit(type) === dataSelection.length}
            color="secondary"
            size="small"
            onClick={() => handleAddDataSelection('entities')}
            style={{
              width: '100%',
              height: 20,
              flex: 1,
            }}
          >
            <AddOutlined fontSize="small" /> {t_i18n('Entities')}
          </Button>
        </Stack>
      )}

      {perspective === 'audits' && (
        <Stack direction="row">
          <Button
            disabled={
              getCurrentDataSelectionLimit(type) === dataSelection.length
              || getCurrentCategory(type) === 'distribution'
            }
            color="secondary"
            size="small"
            onClick={() => handleAddDataSelection('audits')}
            style={{
              width: '100%',
              height: 20,
              flex: 1,
            }}
          >
            <AddOutlined fontSize="small" />
          </Button>
        </Stack>
      )}

      <div style={{ marginTop: 20, textAlign: 'center' }}>
        <Button
          disabled={!isDataSelectionFiltersValid()}
          color="primary"
          style={{
            marginTop: 20,
            textAlign: 'center',
          }}
          onClick={() => setStep(3)}
        >
          {t_i18n('Validate')}
        </Button>
      </div>

      {showRelationCountWarning && (
        <Alert
          content={t_i18n(
            'The amount of results can differ based on the data/relationships, as each occurrence of an inferred relation is counted for this widget.',
          )}
          severity="warning"
          style={{
            marginTop: 20,
          }}
        />
      )}
    </div>
  );
};

export default WidgetCreationDataSelection;
