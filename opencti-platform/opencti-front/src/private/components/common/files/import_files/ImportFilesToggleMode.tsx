import { ImportMode, useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { DescriptionOutlined, RouteOutlined, UploadFileOutlined } from '@mui/icons-material';
import { Box, CardContent } from '@mui/material';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import React from 'react';
import Card from '../../../../../components/common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import { Theme } from '../../../../../components/Theme';

const ImportFilesToggleMode = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { setActiveStep, importMode, setImportMode, entityId, isForcedImportToDraft } = useImportFilesContext();

  const modes: { mode: ImportMode; title: string; description: string; icon: React.ReactElement }[] = [
    {
      mode: 'manual',
      title: t_i18n('Step-by-Step Import'),
      description: t_i18n('A guided workflow that streamlines files import, selection of connectors and allows the creation of a workbench or draft for review before final import'),
      icon: <RouteOutlined sx={{ fontSize: 40, transform: 'rotate(90deg)' }} color="primary" />,
    },
  ];

  if (!isForcedImportToDraft) {
    modes.unshift({
      mode: 'auto',
      title: t_i18n('Direct/Automatic Import'),
      description: t_i18n('Quick import with no configuration needed. Just upload your files and the platform takes care of the rest. Perfect if your file follows a standard format (STIX2.1, MISP).'),
      icon: <UploadFileOutlined sx={{ fontSize: 40 }} color="primary" />,
    });
  }

  // Add form mode only when entityId is not defined (global usage)
  if (!entityId) {
    modes.push({
      mode: 'form',
      title: t_i18n('Import using a Form'),
      description: t_i18n('Use a structured form to create and import data. Select from available forms and fill in the required information to generate properly formatted entities.'),
      icon: <DescriptionOutlined sx={{ fontSize: 40 }} color="primary" />,
    });
  }

  const onSelectMode = (mode: ImportMode) => {
    setImportMode(mode);
    setActiveStep(1);
  };

  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: `repeat(${modes.length}, 1fr)`,
        gap: 1,
      }}
    >
      {modes.map(({ mode, title, description, icon }) => (
        <Card
          aria-label={title}
          variant="outlined"
          onClick={() => onSelectMode(mode)}
          key={mode}
          sx={{
            minWidth: 0,
            textAlign: 'center',
            ...(importMode === mode
              ? { borderColor: theme.palette.primary.main }
              : {}),
          }}
        >
          <CardContent
            sx={{
              height: '100%',
            }}
          >
            <Box>{icon}</Box>
            <Typography
              gutterBottom
              variant="h2"
              sx={{ marginBlock: 2 }}
            >
              {title}
            </Typography>
            <Typography variant="body1">
              {description}
            </Typography>
          </CardContent>
        </Card>
      ))}
    </Box>
  );
};

export default ImportFilesToggleMode;
