import Button from '../../../../components/common/button/Button';
import { graphql, useFragment } from 'react-relay';
import { GoToOpenAEVDrawerFragment$key } from './__generated__/GoToOpenAEVDrawerFragment.graphql';
import { OaevLogo } from '../../../../static/images/logo_oaev';
import { useFormatter } from '../../../../components/i18n';
import { useState } from 'react';
import Drawer from '../../common/drawer/Drawer';
import { Stack, Typography } from '@mui/material';
import { OpenInNewOutlined } from '@mui/icons-material';
import ExternalLinkPopover from '../../../../components/ExternalLinkPopover';

const fragment = graphql`
  fragment GoToOpenAEVDrawerFragment on SecurityCoverage {
    results {
      name
      external_uri
    }
  }
`;

interface GoToOpenAEVDrawerProps {
  data: GoToOpenAEVDrawerFragment$key;
}

const GoToOpenAEVDrawer = ({ data }: GoToOpenAEVDrawerProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [selectedLink, setSelectedLink] = useState<string>();

  const { results } = useFragment(fragment, data);
  const instances = (results ?? []).filter((r) => !!r.external_uri);
  const disabled = instances.length === 0;

  return (
    <>
      <Button
        disabled={disabled}
        startIcon={<OaevLogo />}
        onClick={() => setOpen(true)}
        variant="tertiary"
        size="small"
        sx={{ mt: 2 }}
      >
        {t_i18n('Go to OpenAEV')}
      </Button>

      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        title={t_i18n('Select the OpenAEV instance')}
      >
        <Stack>
          {instances.map((instance) => (
            <Stack direction="row" key={instance.external_uri}>
              <div style={{ flex: 1 }}>
                <Typography>{instance.name}</Typography>
                <Typography variant="body2">{instance.external_uri}</Typography>
              </div>
              <Button
                onClick={() => setSelectedLink(instance.external_uri!)}
                startIcon={<OpenInNewOutlined fontSize="small" />}
              >
                {t_i18n('Browse the link')}
              </Button>
            </Stack>
          ))}
        </Stack>
      </Drawer>

      <ExternalLinkPopover
        externalLink={selectedLink}
        displayExternalLink={!!selectedLink}
        setDisplayExternalLink={() => setSelectedLink('')}
        onConfirm={() => {
          setSelectedLink('');
          setOpen(false);
        }}
      />
    </>
  );
};

export default GoToOpenAEVDrawer;
