import IconButton from '@mui/material/IconButton';
import { AddOutlined, CancelOutlined } from '@mui/icons-material';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import WidgetFilters from '@components/widgets/WidgetFilters';
import Button from '@mui/material/Button';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import type { WidgetPerspective } from '../../../utils/widget/widget';
import { getCurrentCategory, getCurrentDataSelectionLimit } from '../../../utils/widget/widgetUtils';
import { useWidgetConfigContext } from './WidgetConfigContext';

const useStyles = makeStyles<Theme>((theme) => ({
  step_entity: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.secondary.main}`,
    borderRadius: 4,
  },
  step_relationship: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.primary.main}`,
    borderRadius: 4,
  },
  step_audit: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.secondary.main}`,
    borderRadius: 4,
  },
}));

const WidgetCreationDataSelection = () => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const { config, setStep, setDataSelection, setDataSelectionWithIndex } = useWidgetConfigContext();
  const { type, dataSelection, perspective } = config.widget;

  const isDataSelectionFiltersValid = () => {
    return dataSelection.length > 0;
  };

  const handleRemoveDataSelection = (i: number) => {
    const newDataSelection = Array.from(dataSelection);
    newDataSelection.splice(i, 1);
    setDataSelection(newDataSelection);
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
  };

  return (
    <div style={{ marginTop: 20 }}>
      {Array(dataSelection.length)
        .fill(0)
        .map((_, i) => {
          let className = classes.step_entity;
          if (dataSelection[i].perspective === 'relationships') {
            className = classes.step_relationship;
          } else if (dataSelection[i].perspective === 'audits') {
            className = classes.step_audit;
          }
          return (
            <div key={i} className={className}>
              <IconButton
                disabled={dataSelection.length === 1}
                aria-label="Delete"
                style={{
                  position: 'absolute',
                  top: -20,
                  right: -20,
                }}
                onClick={() => handleRemoveDataSelection(i)}
                size="large"
              >
                <CancelOutlined fontSize="small" />
              </IconButton>
              <div style={{ display: 'flex', width: '100%' }}>
                <TextField
                  style={{ flex: 1 }}
                  label={`${t_i18n('Label')} (${dataSelection[i].perspective})`}
                  fullWidth={true}
                  value={dataSelection[i].label}
                  onChange={(event) => handleChangeDataValidationLabel(i, event.target.value)}
                />
                {perspective === 'relationships'
                  && <Tooltip
                    title={t_i18n(
                      'The relationships taken into account are: stix core relationships, sightings and \'contains\' relationships',
                    )}
                     >
                    <InformationOutline
                      fontSize="small"
                      color="primary"
                      style={{ marginRight: 5, marginTop: 20 }}
                    />
                  </Tooltip>}
              </div>
              <WidgetFilters
                dataSelection={dataSelection[i]}
                setDataSelection={(data) => setDataSelectionWithIndex(data, i)}
                perspective={dataSelection[i].perspective ?? perspective}
                type={type}
              />
            </div>
          );
        })}
      {perspective === 'entities' && (
        <div style={{ display: 'flex' }}>
          <Button
            variant="contained"
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
          </Button>
        </div>
      )}
      {perspective === 'relationships' && (
        <div style={{ display: 'flex' }}>
          <Button
            variant="contained"
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
            variant="contained"
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
        </div>
      )}
      {perspective === 'audits' && (
        <div style={{ display: 'flex' }}>
          <Button
            variant="contained"
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
        </div>
      )}
      <div style={{
        marginTop: 20,
        textAlign: 'center',
      }}
      >
        <Button
          disabled={!isDataSelectionFiltersValid()}
          variant="contained"
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
    </div>
  );
};

export default WidgetCreationDataSelection;
