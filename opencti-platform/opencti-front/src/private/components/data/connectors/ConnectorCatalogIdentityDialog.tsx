import React, { FunctionComponent, Suspense, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Box from '@mui/material/Box';
import DialogActions from '@mui/material/DialogActions';
import { Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Combobox, ComboboxContent, ComboboxControls, ComboboxField, ComboboxHelperText, ComboboxInput, ComboboxLabel, ComboboxTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { getConnectorTypeIcon } from '@components/integrations/catalog/utils/ingestionConnectorTypeMetadata';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Theme } from '../../../../components/Theme';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { ConnectorCatalogIdentityValue, isCompatibleCatalogType, sortCatalogOptionsForConnector } from './utils/connectorCatalogIdentity';
import type { ConnectorCatalogIdentityDialogOptionsQuery } from './__generated__/ConnectorCatalogIdentityDialogOptionsQuery.graphql';
import type { ConnectorCatalogIdentityDialogMutation } from './__generated__/ConnectorCatalogIdentityDialogMutation.graphql';

const connectorCatalogIdentityOptionsQuery = graphql`
  query ConnectorCatalogIdentityDialogOptionsQuery {
    connectorCatalogIdentityOptions {
      slug
      title
      logo
      connector_type
      short_description
    }
  }
`;

const connectorCatalogIdentityMutation = graphql`
  mutation ConnectorCatalogIdentityDialogMutation($id: ID!, $slug: String) {
    updateConnectorCatalogIdentity(id: $id, slug: $slug) {
      id
      catalog_identity {
        slug
        title
        logo
        short_description
        source
      }
      catalog_slug_manual
    }
  }
`;

type CatalogOption = ConnectorCatalogIdentityDialogOptionsQuery['response']['connectorCatalogIdentityOptions'][number];

const LOGO_SIZE = 20;

const CatalogLogo: FunctionComponent<{ logo?: string | null; connectorType?: string | null; size: number }> = ({ logo, connectorType, size }) => {
  const theme = useTheme<Theme>();
  if (logo) {
    return <img src={logo} alt="" style={{ width: size, height: size, objectFit: 'contain', borderRadius: 4, flexShrink: 0 }} />;
  }
  const TypeIcon = getConnectorTypeIcon(connectorType ?? '');
  return <TypeIcon sx={{ fontSize: size, color: theme.palette.primary.main, flexShrink: 0 }} />;
};

interface ConnectorCatalogIdentityFormProps {
  queryRef: PreloadedQuery<ConnectorCatalogIdentityDialogOptionsQuery>;
  connector: {
    readonly id: string;
    readonly connector_type?: string | null;
    readonly catalog_identity?: ConnectorCatalogIdentityValue | null;
    readonly catalog_slug_manual?: string | null;
  };
  onClose: () => void;
}

const ConnectorCatalogIdentityForm: FunctionComponent<ConnectorCatalogIdentityFormProps> = ({ queryRef, connector, onClose }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { connectorCatalogIdentityOptions } = usePreloadedQuery(connectorCatalogIdentityOptionsQuery, queryRef);
  const [commit, inFlight] = useApiMutation<ConnectorCatalogIdentityDialogMutation>(connectorCatalogIdentityMutation);

  const options = useMemo(
    () => sortCatalogOptionsForConnector(connectorCatalogIdentityOptions, connector.connector_type),
    [connectorCatalogIdentityOptions, connector.connector_type],
  );
  const currentSlug = connector.catalog_identity?.slug ?? null;
  const [selected, setSelected] = useState<CatalogOption | null>(
    () => options.find((option) => option.slug === currentSlug) ?? null,
  );
  const isManual = connector.catalog_identity?.source === 'manual';
  // A choice made by hand stays stored when its entry leaves the catalog: it can still be removed.
  const hasManualChoice = isManual || Boolean(connector.catalog_slug_manual);

  const submit = (slug: string | null) => {
    commit({
      variables: { id: connector.id, slug },
      onCompleted: () => {
        MESSAGING$.notifySuccess(slug
          ? t_i18n('The catalog entry of the connector has been saved')
          : t_i18n('The connector is identified automatically again'));
        onClose();
      },
    });
  };

  return (
    <>
      <Stack gap={2}>
        <Combobox<CatalogOption>
          options={options}
          value={selected}
          onValueChange={(next) => setSelected((next as CatalogOption | null) ?? null)}
          getOptionLabel={(option) => option.title}
          isOptionEqualToValue={(a, b) => a.slug === b.slug}
          groupBy={(option) => (isCompatibleCatalogType(connector.connector_type, option.connector_type)
            ? t_i18n('Connectors of this type')
            : t_i18n('Other connectors'))}
          renderOption={(option) => (
            <Stack direction="row" alignItems="center" gap={1} sx={{ minWidth: 0 }}>
              <CatalogLogo logo={option.logo} connectorType={option.connector_type} size={LOGO_SIZE} />
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{option.title}</span>
            </Stack>
          )}
        >
          <ComboboxLabel>{t_i18n('Catalog entry')}</ComboboxLabel>
          <ComboboxField>
            <ComboboxInput placeholder={t_i18n('Search the catalog')} />
            <ComboboxControls>
              <ComboboxTrigger />
            </ComboboxControls>
          </ComboboxField>
          <ComboboxHelperText>{t_i18n('The connector takes the logo, title and catalog page of this entry.')}</ComboboxHelperText>
          <ComboboxContent emptyMessage={t_i18n('No catalog entry matches')} listAriaLabel={t_i18n('Catalog entry')} />
        </Combobox>
        {selected && (
          <Stack
            direction="row"
            gap={2}
            alignItems="center"
            data-testid="catalog-identity-preview"
            sx={{
              padding: 2,
              borderRadius: 1,
              border: `1px solid ${theme.palette.divider}`,
            }}
          >
            <CatalogLogo logo={selected.logo} connectorType={selected.connector_type} size={40} />
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>{selected.title}</Typography>
              {selected.short_description && (
                <Typography
                  variant="body2"
                  sx={{
                    color: theme.palette.text.secondary,
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden',
                  }}
                >
                  {selected.short_description}
                </Typography>
              )}
            </Box>
          </Stack>
        )}
      </Stack>
      <DialogActions>
        {hasManualChoice && (
          <Box sx={{ marginRight: 'auto' }}>
            <Button variant="secondary" onClick={() => submit(null)} disabled={inFlight}>
              {t_i18n('Use automatic identification')}
            </Button>
          </Box>
        )}
        <Button variant="secondary" onClick={onClose} disabled={inFlight}>
          {t_i18n('Cancel')}
        </Button>
        <Button
          onClick={() => selected && submit(selected.slug)}
          disabled={inFlight || !selected || (isManual && selected.slug === currentSlug)}
        >
          {t_i18n('Save')}
        </Button>
      </DialogActions>
    </>
  );
};

interface ConnectorCatalogIdentityDialogProps {
  open: boolean;
  onClose: () => void;
  connector: ConnectorCatalogIdentityFormProps['connector'];
}

const ConnectorCatalogIdentityDialog: FunctionComponent<ConnectorCatalogIdentityDialogProps> = ({ open, onClose, connector }) => {
  const { t_i18n } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader<ConnectorCatalogIdentityDialogOptionsQuery>(connectorCatalogIdentityOptionsQuery);

  useEffect(() => {
    if (open) {
      // The catalog changes when the catalog manager synchronises it: every opening refreshes the
      // entries, the store shows the last ones meanwhile.
      loadQuery({}, { fetchPolicy: 'store-and-network' });
    }
  }, [open]);

  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Identify connector')}>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ConnectorCatalogIdentityForm queryRef={queryRef} connector={connector} onClose={onClose} />
        </Suspense>
      )}
    </Dialog>
  );
};

export default ConnectorCatalogIdentityDialog;
