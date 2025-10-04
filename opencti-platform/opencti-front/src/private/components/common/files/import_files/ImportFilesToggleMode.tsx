import React from 'react';
import { ImportMode, useImportFilesContext } from '@private/components/common/files/import_files/ImportFilesContext';
import { RouteOutlined, UploadFileOutlined, DescriptionOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../../components/i18n';
import { Box, Card, CardActionArea, CardContent, Typography } from '@components';

const CARD_WIDTH = 450;
const CARD_HEIGHT = 300;

const ImportFilesToggleMode = () => {
  const { t_i18n } = useFormatter();
  const { setActiveStep, importMode, setImportMode, entityId } = useImportFilesContext();
  const modes: { mode: ImportMode, title: string, description: string, icon: React.ReactElement }[] = [
    {
      mode: 'auto',
      title: t_i18n('Direct/Automatic Import'),
      description: t_i18n('Quick import with no configuration needed. Just upload your files and the platform takes care of the rest. Perfect if your file follows a standard format (STIX2.1, MISP).'),
      icon: <UploadFileOutlined sx={{ fontSize: 40 }} color="primary"/>,
    },
    {
      mode: 'manual',
      title: t_i18n('Step-by-Step Import'),
      description: t_i18n('A guided workflow that streamlines files import, selection of connectors and allows the creation of a workbench or draft for review before final import'),
      icon: <RouteOutlined sx={{ fontSize: 40, transform: 'rotate(90deg)' }} color="primary"/>,
    },
  ];

  // Add form mode only when entityId is not defined (global usage)
  if (!entityId) {
    modes.push({
      mode: 'form',
      title: t_i18n('Import using a Form'),
      description: t_i18n('Use a structured form to create and import data. Select from available forms and fill in the required information to generate properly formatted entities.'),
      icon: <DescriptionOutlined sx={{ fontSize: 40 }} color="primary"/>,
    });
  }

  const onSelectMode = (mode: ImportMode) => {
    setImportMode(mode);
    setActiveStep(1);
  };

  return (
    <Box
      sx={{
        display: 'flex',
        gap: 4,
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '60vh',
        flexWrap: 'wrap',
      }}
    >
      {modes.map(({ mode, title, description, icon }) => (
        <Card
          variant="outlined"
          key={mode}
          style={{
            width: CARD_WIDTH,
            height: CARD_HEIGHT,
            textAlign: 'center',
          }}
        >
          <CardActionArea
            onClick={() => onSelectMode(mode)}
            data-active={importMode === mode ? '' : undefined}
            sx={{
              height: '100%',
              '&[data-active]': {
                backgroundColor: 'action.selected',
                '&:hover': {
                  backgroundColor: 'action.selectedHover',
                },
              },
            }}
            aria-label={title}
          >
            <CardContent>
              {icon}
              <Typography
                gutterBottom
                variant="h2"
                style={{ marginTop: 20 }}
              >
                {title}
              </Typography>
              <br/>
              <Typography variant="body1">
                {description}
              </Typography>
            </CardContent>
          </CardActionArea>
        </Card>
      ))}
    </Box>
  );
};

export default ImportFilesToggleMode;
