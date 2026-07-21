import React from 'react';
import { CardActions, Stack, Typography } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { BuiltInIntegrationDefinition } from '@components/integrations/available/builtInIntegrations';
import { DeployedCountChip } from '@components/integrations/components/MarketplaceUi';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import Card from '../../../../components/common/card/Card';

export interface BuiltInIntegrationCardProps {
  definition: BuiltInIntegrationDefinition;
  deploymentCount: number;
  onClickCreate: () => void;
}

const BuiltInIntegrationCard = ({ definition, deploymentCount, onClickCreate }: BuiltInIntegrationCardProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const Icon = definition.icon;
  // The whole card triggers the creation, like the connector cards open their
  // detail: only when the user is granted to create ingestion instances.
  const canCreate = useGranted([INGESTION_SETINGESTIONS]);

  return (
    <Box
      data-testid="builtin-card"
      sx={{
        height: '100%',
        '& .MuiCard-root': {
          border: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
          transition: 'transform 0.3s ease-in-out, border-color 0.3s ease-in-out, box-shadow 0.3s ease-in-out',
        },
        '&:hover .MuiCard-root': {
          transform: 'translateY(-2px)',
          borderColor: alpha(theme.palette.primary.main, 0.3),
          boxShadow: `0 0 30px ${alpha(theme.palette.primary.main, 0.12)}`,
        },
      }}
    >
      <Card
        onClick={canCreate ? onClickCreate : undefined}
        sx={{
          height: 280,
          borderRadius: 1,
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          alignItems: 'stretch',
          cursor: canCreate ? 'pointer' : undefined,
        }}
      >
        <Stack direction="row" gap={1.5} alignItems="flex-start" sx={{ width: '100%' }}>
          <Box
            sx={{
              height: 56,
              width: 56,
              flexShrink: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: 1,
              border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
              backgroundColor: alpha(theme.palette.primary.main, 0.08),
            }}
          >
            <Icon sx={{ fontSize: 28, color: theme.palette.primary.main }} />
          </Box>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography
              variant="body2"
              sx={{
                color: theme.palette.primary.main,
                fontSize: 12,
                fontWeight: 500,
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                marginBottom: 0.5,
              }}
            >
              {t_i18n('Built-in')}
            </Typography>
            <Typography
              sx={{
                fontSize: 15,
                fontWeight: 600,
                lineHeight: 1.35,
                display: '-webkit-box',
                WebkitLineClamp: 2,
                WebkitBoxOrient: 'vertical',
                overflow: 'hidden',
                wordBreak: 'break-word',
              }}
            >
              {t_i18n(definition.label)}
            </Typography>
          </Box>
        </Stack>

        <Box sx={{ flexGrow: 1, overflow: 'hidden', width: '100%' }}>
          <Typography
            variant="body2"
            sx={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              display: '-webkit-box',
              WebkitLineClamp: 4,
              WebkitBoxOrient: 'vertical',
              lineHeight: 1.5,
              color: theme.palette.text.secondary,
            }}
          >
            {t_i18n(definition.description)}
          </Typography>
        </Box>

        <CardActions
          sx={{
            width: '100%',
            justifyContent: 'space-between',
            padding: 0,
            flexWrap: 'nowrap',
            gap: 1,
            alignItems: 'center',
          }}
        >
          <DeployedCountChip
            count={deploymentCount}
            to={`/dashboard/integrations/deployed?type=${definition.kind}`}
          />
          <Security needs={[INGESTION_SETINGESTIONS]}>
            <Button
              size="small"
              onClick={(event) => {
                event.stopPropagation();
                onClickCreate();
              }}
              sx={{ marginLeft: 'auto' }}
            >
              {t_i18n('Create')}
            </Button>
          </Security>
        </CardActions>
      </Card>
    </Box>
  );
};

export default BuiltInIntegrationCard;
