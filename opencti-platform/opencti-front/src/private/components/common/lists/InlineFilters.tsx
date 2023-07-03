import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { BackupTableOutlined, CampaignOutlined, HighlightOff, HorizontalRule } from '@mui/icons-material';
import { CheckCircleOutline } from 'mdi-material-ui';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import React, { FunctionComponent, SyntheticEvent } from 'react';
import InputLabel from '@mui/material/InputLabel';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';

interface BooleanFilterProps {
  filterKey: string,
  handleSwitchFilter: (key: string, id: string, value: string, event?: SyntheticEvent) => void,
  defaultHandleRemoveFilter: (key: string) => void,
}

const useStyles = makeStyles(() => ({
  inputLabel: {
    margin: '8px 15px 0 10px',
    fontSize: 14,
    float: 'left',
  },
}));

const InlineFilters: FunctionComponent<BooleanFilterProps> = ({ filterKey, handleSwitchFilter, defaultHandleRemoveFilter }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const handleInputValues = (value: string) => {
    defaultHandleRemoveFilter(filterKey);
    if (value !== '') {
      handleSwitchFilter(filterKey, value, t(value));
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
            <Tooltip title={t('No filtering')}>
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
            <Tooltip title={t('Regular digest')}>
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
            <Tooltip title={t('Live trigger')}>
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
            <Tooltip title={t('No filtering')}>
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
            <Tooltip title={t('Yes')}>
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
            <Tooltip title={t('No')}>
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
    <div>
      <InputLabel
        classes={{ root: classes.inputLabel }}
      >
        {t(`filter_${filterKey}`)}
      </InputLabel>
      {booleanFilterContent()}
    </div>
  );
};

export default InlineFilters;
