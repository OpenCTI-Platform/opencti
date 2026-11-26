import Button from '../../../../components/common/button/Button';
import { graphql, useFragment } from 'react-relay';
import { GoToOpenAEVDrawerFragment$key } from './__generated__/GoToOpenAEVDrawerFragment.graphql';
import openAevMark from '../../../../static/images/logo_oaev.svg';
import { XtmMark } from '../../common/xtm/counterpart/core/XtmMark';
import { useFormatter } from '../../../../components/i18n';
import { useState } from 'react';
import Drawer from '../../common/drawer/Drawer';
import { List, ListItemButton, ListItemIcon, ListItemText } from '@mui/material';
import { OpenInNewOutlined } from '@mui/icons-material';
import { distinctOpenAEVLinks } from './openAEVLinks';

const fragment = graphql`
  fragment GoToOpenAEVDrawerFragment on SecurityCoverage {
    results {
      id
      name
      external_uri
    }
  }
`;

interface GoToOpenAEVDrawerProps {
  data: GoToOpenAEVDrawerFragment$key;
}

// OpenAEV is a connected XTM product: its link opens in a new tab, like the XTM emblem's "Open in" buttons.
const GoToOpenAEVDrawer = ({ data }: GoToOpenAEVDrawerProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);

  const { results } = useFragment(fragment, data);
  const links = distinctOpenAEVLinks(results);

  if (links.length === 0) {
    return null;
  }

  if (links.length === 1) {
    return (
      <Button
        startIcon={<XtmMark src={openAevMark} />}
        href={links[0].url}
        target="_blank"
        rel="noopener noreferrer"
        variant="tertiary"
        size="small"
        sx={{ mt: 2 }}
      >
        {t_i18n('Go to OpenAEV')}
      </Button>
    );
  }

  return (
    <>
      <Button
        startIcon={<XtmMark src={openAevMark} />}
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
        <List disablePadding>
          {links.map((link) => (
            <ListItemButton
              key={link.url}
              component="a"
              href={link.url}
              target="_blank"
              rel="noopener noreferrer"
              title={link.url}
              divider
              onClick={() => setOpen(false)}
            >
              <ListItemText primary={link.label} secondary={link.label === link.host ? undefined : link.host} />
              <ListItemIcon sx={{ minWidth: 0, ml: 2 }}>
                <OpenInNewOutlined fontSize="small" />
              </ListItemIcon>
            </ListItemButton>
          ))}
        </List>
      </Drawer>
    </>
  );
};

export default GoToOpenAEVDrawer;
