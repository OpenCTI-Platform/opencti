import { Link } from 'react-router-dom';

import Box from '@mui/material/Box';
import { DoNotDisturbOnOutlined, OpenInNew } from '@mui/icons-material';
import { useFormatter } from '../../i18n';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../Theme';
import { Typography } from '@mui/material';

type DataTableSearchEmptyStateProps = {
  rawSearchTerm: string | undefined;
};

const DataTableSearchEmptyState = ({ rawSearchTerm }: DataTableSearchEmptyStateProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        py: 6,
        px: 2,
        width: '100%',
      }}
    >
      <DoNotDisturbOnOutlined sx={{ fontSize: 40, color: theme.palette.text.disabled, mb: 1 }} />
      <Typography variant="h6" sx={{ color: theme.palette.text.secondary, mb: 2 }}>
        {rawSearchTerm ? `${t_i18n('No results for')} "${rawSearchTerm}"` : t_i18n('No results')}
      </Typography>
      {rawSearchTerm && (
        <Typography variant="body1">
          {t_i18n('Learn more about search options in {link}', {
            values: {
              link: (
                <Link
                  target="_blank"
                  rel="noopener noreferrer"
                  to="https://docs.opencti.io/latest/usage/search/#search-syntax"
                >
                  {t_i18n('our documentation')}
                  <OpenInNew sx={{ fontSize: 14, pl: '2px', verticalAlign: 'middle', pb: '2px' }} />
                </Link>
              ),
            },
          })}
        </Typography>
      )}
    </Box>
  );
};

export default DataTableSearchEmptyState;
