import React, { FunctionComponent, useState } from 'react';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import { Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import Card from '../../../../components/common/card/Card';
import Tag from '../../../../components/common/tag/Tag';
import type { Theme } from '../../../../components/Theme';
import useGranted, { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import ConnectorCatalogIdentityDialog from './ConnectorCatalogIdentityDialog';
import { canIdentifyConnector, catalogIdentityHint, catalogIdentityHintDescription, ConnectorCatalogIdentityValue, isSameConnectorName } from './utils/connectorCatalogIdentity';

interface ConnectorCatalogIdentityCardProps {
  connector: {
    readonly id: string;
    readonly name: string;
    readonly connector_type?: string | null;
    readonly is_managed?: boolean | null;
    readonly built_in?: boolean | null;
    readonly catalog_identity?: (ConnectorCatalogIdentityValue & { readonly short_description?: string | null }) | null;
    readonly catalog_slug_manual?: string | null;
  };
}

// Catalog entry of a self-deployed connector: what it is, how the platform recognised it, and the
// manual choice when the platform could not tell.
const ConnectorCatalogIdentityCard: FunctionComponent<ConnectorCatalogIdentityCardProps> = ({ connector }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const canManage = useGranted([MODULES_MODMANAGE]);
  const [dialogOpen, setDialogOpen] = useState(false);

  if (!canIdentifyConnector(connector)) {
    return null;
  }
  const identity = connector.catalog_identity;
  if (!identity && !canManage) {
    return null;
  }

  const hint = catalogIdentityHint(identity?.source, t_i18n);
  // The page header shows the name of the connector: the catalog title is only repeated when it differs.
  const showTitle = !!identity && !isSameConnectorName(identity.title, connector.name);
  const dialog = canManage && (
    <ConnectorCatalogIdentityDialog open={dialogOpen} onClose={() => setDialogOpen(false)} connector={connector} />
  );

  if (!identity) {
    return (
      <Box sx={{ marginBottom: '20px' }}>
        <Card title={t_i18n('About this connector')}>
          <Stack direction="row" alignItems="center" justifyContent="space-between" gap={2}>
            <Typography variant="body2" sx={{ color: theme.palette.text.secondary }}>
              {t_i18n('This connector is not linked to a catalog entry.')}
            </Typography>
            <Button variant="secondary" size="small" onClick={() => setDialogOpen(true)}>
              {t_i18n('Identify connector')}
            </Button>
          </Stack>
        </Card>
        {dialog}
      </Box>
    );
  }

  return (
    <Box sx={{ marginBottom: '20px' }}>
      <Card
        title={t_i18n('About this connector')}
        action={hint && (
          <Tag
            label={hint}
            size="small"
            labelTextTransform="none"
            tooltipTitle={catalogIdentityHintDescription(identity.source, t_i18n)}
          />
        )}
      >
        <Stack gap={1.5}>
          {(showTitle || identity.short_description) && (
            <Stack gap={0.5}>
              {showTitle && (
                <Typography variant="body1" sx={{ fontWeight: 600 }}>
                  {identity.title}
                </Typography>
              )}
              {identity.short_description && (
                <Typography variant="body2" sx={{ color: theme.palette.text.secondary }}>
                  {identity.short_description}
                </Typography>
              )}
            </Stack>
          )}
          <Stack direction="row" gap={1} flexWrap="wrap">
            <Button
              variant="secondary"
              size="small"
              component={Link}
              to={`/dashboard/integrations/catalog/${identity.slug}`}
            >
              {t_i18n('View in catalog')}
            </Button>
            {canManage && (
              <Button variant="secondary" size="small" onClick={() => setDialogOpen(true)}>
                {t_i18n('Change catalog entry')}
              </Button>
            )}
          </Stack>
        </Stack>
      </Card>
      {dialog}
    </Box>
  );
};

export default ConnectorCatalogIdentityCard;
