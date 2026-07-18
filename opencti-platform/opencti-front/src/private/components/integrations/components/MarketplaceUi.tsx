import React, { useContext } from 'react';
import { Box, Stack, Typography } from '@mui/material';
import { Search } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';
import { alpha, useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import GradientCard from '../../../../components/GradientCard';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { isNotEmptyField } from '../../../../utils/utils';

export const BrowseMoreButton = () => {
  const { t_i18n } = useFormatter();
  const { settings } = useContext(UserContext);
  const browseHubCatalog = isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings.platform_xtmhub_url}/cybersecurity-solutions/open-cti-integrations`
    : '';
  return (
    <Button
      gradient
      variant="secondary"
      href={browseHubCatalog}
      target="_blank"
      title={t_i18n('Browse More')}
    >
      {t_i18n('Browse More')}
    </Button>
  );
};

interface HeroStatChipProps {
  icon: SvgIconComponent;
  value: number;
  label: string;
}

export const HeroStatChip = ({ icon: Icon, value, label }: HeroStatChipProps) => {
  const theme = useTheme();
  return (
    <Stack
      direction="row"
      alignItems="center"
      gap={0.75}
      sx={{
        paddingInline: 1.25,
        paddingBlock: 0.5,
        borderRadius: 1,
        border: `1px solid ${alpha(theme.palette.text.primary, 0.1)}`,
        backgroundColor: alpha(theme.palette.text.primary, 0.04),
      }}
    >
      <Icon sx={{ fontSize: 16, color: theme.palette.primary.main }} />
      <Typography sx={{ fontSize: 13, fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </Typography>
      <Typography sx={{ fontSize: 13, color: theme.palette.text.secondary }}>
        {label}
      </Typography>
    </Stack>
  );
};

interface MarketplaceSectionHeaderProps {
  icon: SvgIconComponent;
  label: string;
  count: number;
}

export const MarketplaceSectionHeader = ({ icon: Icon, label, count }: MarketplaceSectionHeaderProps) => {
  const theme = useTheme();
  return (
    <Stack direction="row" alignItems="center" gap={1.25} sx={{ marginBottom: 1.5 }}>
      <Box
        sx={{
          width: 28,
          height: 28,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: 1,
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
          backgroundColor: alpha(theme.palette.primary.main, 0.1),
        }}
      >
        <Icon sx={{ fontSize: 15, color: theme.palette.primary.main }} />
      </Box>
      <Typography
        component="h2"
        sx={{
          fontFamily: theme.typography.h1.fontFamily,
          fontSize: 16,
          fontWeight: 600,
        }}
      >
        {label}
      </Typography>
      <Box
        component="span"
        sx={{
          paddingInline: 0.75,
          paddingBlock: '1px',
          borderRadius: 0.5,
          backgroundColor: alpha(theme.palette.text.primary, 0.06),
          fontSize: 11,
          fontWeight: 500,
          fontVariantNumeric: 'tabular-nums',
          color: theme.palette.text.secondary,
        }}
      >
        {count}
      </Box>
      <Box sx={{ flex: 1, height: '1px', backgroundColor: alpha(theme.palette.text.primary, 0.05) }} />
    </Stack>
  );
};

export const ResultCountChip = ({ count }: { count: number }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  return (
    <Box
      component="span"
      sx={{
        marginLeft: 'auto',
        paddingInline: 1.25,
        paddingBlock: 0.5,
        borderRadius: 1,
        backgroundColor: alpha(theme.palette.text.primary, 0.06),
        fontSize: 13,
        fontWeight: 500,
        fontVariantNumeric: 'tabular-nums',
        color: theme.palette.text.secondary,
      }}
    >
      {(() => {
        if (count === 1) return t_i18n('1 result');
        return t_i18n('{count} results', { values: { count } });
      })()}
    </Box>
  );
};

interface MarketplaceEmptyStateProps {
  hasActiveFilters: boolean;
  onResetFilters: () => void;
  extraAction?: React.ReactNode;
}

export const MarketplaceEmptyState = ({ hasActiveFilters, onResetFilters, extraAction }: MarketplaceEmptyStateProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Stack
      justifyContent="center"
      alignItems="center"
      sx={{
        minHeight: '40vh',
      }}
    >
      <GradientCard sx={{
        px: 10,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 4,
      }}
      >
        <Stack flexDirection="row" alignItems="flex-start" gap={1}>
          <GradientCard.Icon icon={Search} size="large" />
          <Stack>
            <GradientCard.Text sx={{ whiteSpace: 'pre' }}>{t_i18n('Sorry, we couldn\'t find any results for your search.')}</GradientCard.Text>
            <GradientCard.Text sx={{ whiteSpace: 'pre' }}>{t_i18n('For more results, you can search in the ecosystem.')}</GradientCard.Text>
          </Stack>
        </Stack>
        <Stack direction="row" gap={2}>
          {hasActiveFilters && (
            <Button variant="secondary" onClick={onResetFilters}>
              {t_i18n('Reset filters')}
            </Button>
          )}
          {extraAction}
        </Stack>
      </GradientCard>
    </Stack>
  );
};
