import { Box, CardContent, Typography } from '@mui/material';
import { AutoModeOutlined, EditOutlined } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';
import Card from 'src/components/common/card/Card';
import Button from 'src/components/common/button/Button';
import { SecurityCoverageMode } from './securityCoverageCreation-types';

const CARD_WIDTH = 400;
const CARD_HEIGHT = 250;

interface ChooseModeStepProps {
  hasEnrichmentConnectors: boolean;
  onSelectMode: (mode: SecurityCoverageMode) => void;
  onClose: () => void;
}

const ChooseModeStep = ({
  hasEnrichmentConnectors,
  onSelectMode,
  onClose,
}: ChooseModeStepProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Box>
      <Box
        sx={{
          display: 'flex',
          gap: 4,
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '40vh',
          flexWrap: 'wrap',
          marginTop: 4,
        }}
      >
        <Card
          aria-label={t_i18n('Manual Input')}
          variant="outlined"
          onClick={() => onSelectMode(SecurityCoverageMode.MANUAL)}
          sx={{
            width: CARD_WIDTH,
            height: CARD_HEIGHT,
            textAlign: 'center',
          }}
        >
          <CardContent>
            <EditOutlined sx={{ fontSize: 40 }} color="primary" />
            <Typography
              gutterBottom
              variant="h2"
              sx={{ marginTop: 2.5 }}
            >
              {t_i18n('Manual Input')}
            </Typography>
            <br />
            <Typography variant="body1">
              {t_i18n('Manually enter security coverage metrics and scores for this entity')}
            </Typography>
          </CardContent>
        </Card>

        <Card
          variant="outlined"
          aria-label={t_i18n('Automated using enrichment')}
          onClick={() => hasEnrichmentConnectors && onSelectMode(SecurityCoverageMode.AUTO)}
          disabled={!hasEnrichmentConnectors}
          sx={{
            width: CARD_WIDTH,
            height: CARD_HEIGHT,
            textAlign: 'center',
            opacity: hasEnrichmentConnectors ? 1 : 0.5,
          }}
        >
          <CardContent>
            <AutoModeOutlined sx={{ fontSize: 40 }} color={hasEnrichmentConnectors ? 'primary' : 'disabled'} />
            <Typography
              gutterBottom
              variant="h2"
              sx={{ marginTop: 2.5 }}
              color={hasEnrichmentConnectors ? 'textPrimary' : 'textSecondary'}
            >
              {t_i18n('Automated using enrichment')}
            </Typography>
            <br />
            <Typography
              variant="body1"
              color={hasEnrichmentConnectors ? 'textPrimary' : 'textSecondary'}
            >
              {hasEnrichmentConnectors
                ? t_i18n('OpenAEV (or other AEV platforms) can be used to automate security coverage assessment')
                : t_i18n('No enrichment connector available for Security Coverage')}
            </Typography>
          </CardContent>
        </Card>
      </Box>
      <Box sx={{ marginTop: 2.5, textAlign: 'right' }}>
        <Button
          onClick={onClose}
          sx={{ marginLeft: 2 }}
        >
          {t_i18n('Cancel')}
        </Button>
      </Box>
    </Box>
  );
};

export default ChooseModeStep;
