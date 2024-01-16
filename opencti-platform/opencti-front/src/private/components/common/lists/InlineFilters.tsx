import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { BackupTableOutlined, CampaignOutlined, HighlightOff, HorizontalRule } from '@mui/icons-material';
import { CheckCircleOutline } from 'mdi-material-ui';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import React, { FunctionComponent } from 'react';
import InputLabel from '@mui/material/InputLabel';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';

interface BooleanFilterProps {
  filterKey: string,
  handleSwitchFilter?: HandleAddFilter,
  defaultHandleRemoveFilter?: (key: string) => void,
}

const useStyles = makeStyles(() => ({
  inputLabel: {
    margin: '8px 15px 0 10px',
    fontSize: 14,
    float: 'left',
  },
}));

const InlineFilters: FunctionComponent<BooleanFilterProps> = ({ filterKey, handleSwitchFilter, defaultHandleRemoveFilter }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const handleInputValues = (value: string) => {
    if (defaultHandleRemoveFilter && handleSwitchFilter) {
      defaultHandleRemoveFilter(filterKey);
      if (value !== '') {
        handleSwitchFilter(filterKey, value);
      }
    }
  };

  const booleanFilterContent = () => {
    switch (filterKey) {
      case 'trigger_type':
        return (
          <ToggleButtonGroup
            size="small"
            color="secondary"
            exclusive={true}
            style={{ marginRight: '15px' }}
          >
            <Tooltip title={t_i18n('No filtering')}>
              <ToggleButton
                onClick={(_, value) => handleInputValues(value)}
                value=""
              >
                <HorizontalRule
                  fontSize="small"
                  color={'primary'}
                />
              </ToggleButton>
            </Tooltip>
            <Tooltip title={t_i18n('Regular digest')}>
              <ToggleButton
                onClick={(_, value) => handleInputValues(value)}
                value="digest"
              >
                <BackupTableOutlined
                  fontSize="small"
                  color={'primary'}
                />
              </ToggleButton>
            </Tooltip>
            <Tooltip title={t_i18n('Live trigger')}>
              <ToggleButton
                onClick={(_, value) => handleInputValues(value)}
                value="live"
              >
                <CampaignOutlined
                  fontSize="small"
                  color={'primary'}
                />
              </ToggleButton>
            </Tooltip>
          </ToggleButtonGroup>
        );
      default:
        return (
          <ToggleButtonGroup
            size="small"
            color="secondary"
            exclusive={true}
            style={{ marginRight: '15px' }}
          >
            <Tooltip title={t_i18n('No filtering')}>
              <ToggleButton
                onClick={(_, value) => handleInputValues(value)}
                value=""
              >
                <HorizontalRule
                  fontSize="small"
                  color={'primary'}
                />
              </ToggleButton>
            </Tooltip>
            <Tooltip title={t_i18n('Yes')}>
              <ToggleButton
                onClick={(_, value) => handleInputValues(value)}
                value="true"
              >
                <CheckCircleOutline
                  fontSize="small"
                  color={'primary'}
                />
              </ToggleButton>
            </Tooltip>
            <Tooltip title={t_i18n('No')}>
              <ToggleButton
                onClick={(_, value) => handleInputValues(value)}
                value="false"
              >
                <HighlightOff
                  fontSize="small"
                  color={'primary'}
                />
              </ToggleButton>
            </Tooltip>
          </ToggleButtonGroup>
        );
    }
  };
  return (
    <>
      <InputLabel
        classes={{ root: classes.inputLabel }}
      >
        {t_i18n(filterKey)}
      </InputLabel>
      {booleanFilterContent()}
    </>
  );
};

export default InlineFilters;
