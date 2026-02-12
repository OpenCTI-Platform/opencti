import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { ContainerStixCoreObjectsSuggestedMappingQuery$data } from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingQuery.graphql';
import { CheckCircleOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import Switch from '@mui/material/Switch';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';

interface ContainerStixCoreObjectsMappingHeaderProps {
  suggestedMappingData: ContainerStixCoreObjectsSuggestedMappingQuery$data;
  validateDisabled: boolean;
  openValidate: boolean;
  setOpenValidate: (openValidate: boolean) => void;
  handleValidateMapping: () => void;
  validating: boolean;
  openClearMapping: boolean;
  setOpenClearMapping: (openClearMapping: boolean) => void;
  handleClearMapping: () => void;
  clearing: boolean;
  inSuggestedMode: boolean;
  setInSuggestedMode: (inSuggestedMode: boolean) => void;
  askingSuggestion: boolean;
  handleAskNewSuggestion: () => void;
}

const ContainerStixCoreObjectsMappingHeader: FunctionComponent<ContainerStixCoreObjectsMappingHeaderProps> = ({
  suggestedMappingData,
  validateDisabled,
  openValidate,
  setOpenValidate,
  handleValidateMapping,
  validating,
  openClearMapping,
  setOpenClearMapping,
  clearing,
  handleClearMapping,
  inSuggestedMode,
  setInSuggestedMode,
  askingSuggestion,
  handleAskNewSuggestion,
}) => {
  const { t_i18n } = useFormatter();
  const hasConnectorsAvailable = suggestedMappingData.connectorsForAnalysis?.length ? suggestedMappingData.connectorsForAnalysis.length > 0 : false;

  return (
    <>
      <Dialog
        open={openValidate}
        onClose={() => setOpenValidate(false)}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('You are about to validate this mapping, it will add suggested entities to your container.')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setOpenValidate(false)}
            disabled={validating}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleValidateMapping}
            disabled={validating}
          >
            {t_i18n('Validate')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={openClearMapping}
        onClose={() => setOpenClearMapping(false)}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to delete the mapping of this content?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setOpenClearMapping(false)}
            disabled={clearing}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={() => handleClearMapping()}
            disabled={clearing}
          >
            {t_i18n('Clear')}
          </Button>
        </DialogActions>
      </Dialog>
      <Box sx={{ display: 'flex', alignItems: 'center' }}>
        <FormGroup>
          <FormControlLabel
            control={(
              <Switch
                checked={inSuggestedMode}
                onChange={() => {
                  setInSuggestedMode(!inSuggestedMode);
                }}
                disabled={askingSuggestion || validating || suggestedMappingData.stixCoreObjectAnalysis?.analysisStatus !== 'complete'}
              />
            )}
            label={t_i18n('Show suggested mapping')}
          />
        </FormGroup>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', marginLeft: 'auto' }}>
          {!hasConnectorsAvailable && (
            <Tooltip
              title={t_i18n('An analysis connector needs to be available to ask for a mapping suggestion.')}
            >
              <InformationOutline fontSize="small" color="primary" />
            </Tooltip>
          )}
          {askingSuggestion && (
            <Tooltip
              title={t_i18n('An analysis is ongoing, waiting for results.')}
            >
              <InformationOutline fontSize="small" color="primary" />
            </Tooltip>
          )}
          <Tooltip title={t_i18n('Ask new mapping')}>
            <Button
              size="small"
              onClick={handleAskNewSuggestion}
              disabled={!hasConnectorsAvailable || askingSuggestion}
            >
              {t_i18n('Ask new mapping')}
            </Button>
          </Tooltip>
          {!inSuggestedMode && (
            <Tooltip title={t_i18n('Clear mappings')}>
              <Button
                onClick={() => setOpenClearMapping(true)}
                size="small"
              >
                {t_i18n('Clear mappings')}
              </Button>
            </Tooltip>
          )}
          {inSuggestedMode && (
            <Tooltip title={t_i18n('Validate suggested mapping')}>
              <Button
                onClick={() => setOpenValidate(true)}
                startIcon={<CheckCircleOutlined />}
                size="small"
                disabled={validateDisabled}
              >
                {t_i18n('Validate')}
              </Button>
            </Tooltip>
          )}
        </Box>
      </Box>
    </>
  );
};

export default ContainerStixCoreObjectsMappingHeader;
