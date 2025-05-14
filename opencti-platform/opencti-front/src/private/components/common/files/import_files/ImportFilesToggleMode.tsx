import React from 'react';
import { ImportMode, useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { Box, Card, CardActionArea, CardContent } from '@mui/material';
import Typography from '@mui/material/Typography';
import { RouteOutlined, UploadFileOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../../components/i18n';

const CARD_WIDTH = 450;
const CARD_HEIGHT = 300;

const ImportFilesToggleMode = () => {
  const { t_i18n } = useFormatter();
  const { setActiveStep, importMode, setImportMode } = useImportFilesContext();
  const modes: { mode: ImportMode, title: string, description: string }[] = [
    {
      mode: 'auto',
      title: t_i18n('Direct/Automatic Import'),
      description: t_i18n('Quick import with no configuration needed. Just upload your files and the platform takes care of the rest. Perfect if your file follows a standard format (STIX2.1, MISP).'),
    },
    {
      mode: 'manual',
      title: t_i18n('Step-by-Step Import'),
      description: t_i18n('A guided workflow that streamlines files import, selection of connectors and allows the creation of a workbench or draft for review before final import'),
    },
  ];

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
        minHeight: '50vh',
        flexWrap: 'wrap',
      }}
    >
      {modes.map(({ mode, title, description }) => (
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
              {mode === 'auto' ? (<UploadFileOutlined sx={{ fontSize: 40 }} color="primary"/>) : (
                <RouteOutlined sx={{ fontSize: 40, transform: 'rotate(90deg)' }} color="primary"/>)}
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
