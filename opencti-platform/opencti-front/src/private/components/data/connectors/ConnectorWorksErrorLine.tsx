import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import Button from '@mui/material/Button';
import React, { FunctionComponent, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import IconButton from '@mui/material/IconButton';
import { InfoOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { ParsedWorkMessage, ResolvedEntity } from '@components/data/connectors/parseWorkErrors';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import ItemCopy from '../../../../components/ItemCopy';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';

interface ConnectorWorksErrorLineProps {
  error: ParsedWorkMessage;
}

const ConnectorWorksErrorLine: FunctionComponent<ConnectorWorksErrorLineProps> = ({ error }) => {
  const { t_i18n, nsdt } = useFormatter();
  const [openModalErrorDetails, setOpenModalErrorDetails] = useState<boolean>(false);
  const truncateLimit = 80;

  const handleToggleModalError = () => {
    setOpenModalErrorDetails(!openModalErrorDetails);
  };

  if (!error.rawError) {
    return null;
  }

  const entityListItem = (entity: ResolvedEntity) => {
    const name = entity.representative?.main;
    return (
      <div>
        {entity.entity_type ? (
          <Tooltip title={name}>
            <a href={`/dashboard/id/${entity.id}`} target="_blank" rel="noreferrer">
              [{entity.entity_type}] {truncate(name, truncateLimit)}
            </a>
          </Tooltip>
        ) : (
          <div>{entity.standard_id}</div>
        )}
      </div>
    );
  };

  return (
    <>
      <TableRow key={error.rawError.timestamp}>
        <TableCell>{nsdt(error.rawError.timestamp)}</TableCell>
        <TableCell>
          {error.isParsed ? (
            <a href={`https://docs.opencti.io/latest/deployment/troubleshooting/#${error.parsedError.category}`} target="_blank" rel="noreferrer">{error.parsedError.category}</a>
          ) : (
            <a href={'https://docs.opencti.io/latest/deployment/troubleshooting'} target="_blank" rel="noreferrer">{t_i18n('Unknown')}</a>
          )}
        </TableCell>
        <TableCell>{error.isParsed ? error.parsedError.message : error.rawError.message}</TableCell>
        <TableCell>
          {error.isParsed ? (
            entityListItem(error.parsedError.entity)
          ) : (
            truncate(error.rawError.source, truncateLimit)
          )}
        </TableCell>
        <TableCell>
          <Tooltip title={t_i18n('Details')}>
            <IconButton
              onClick={handleToggleModalError}
              aria-haspopup="true"
              color="primary"
            >
              <InfoOutlined />
            </IconButton>
          </Tooltip>
        </TableCell>
      </TableRow>

      <Dialog
        PaperProps={{ elevation: 1 }}
        open={openModalErrorDetails}
        TransitionComponent={Transition}
        onClose={handleToggleModalError}
      >
        <DialogTitle>{t_i18n('Details')}</DialogTitle>
        <DialogContent sx={{ minWidth: '500px' }}>
          <DialogContentText>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('Entities')}
            </Typography>
            <Paper
              style={{
                padding: '15px',
                borderRadius: 4,
                marginBottom: '15px',
              }}
              variant="outlined"
            >
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: 15 }}>
                <div>
                  <Typography variant="h3" gutterBottom={true}>{t_i18n('Entity')}</Typography>
                  {error.isParsed ? entityListItem(error.parsedError.entity) : '-'}
                </div>
                <div>
                  <Typography variant="h3" gutterBottom={true}>{t_i18n('From')}</Typography>
                  {error.isParsed && error.parsedError.entity.from ? entityListItem(error.parsedError.entity.from) : '-'}
                </div>
                <div>
                  <Typography variant="h3" gutterBottom={true}>{t_i18n('To')}</Typography>
                  {error.isParsed && error.parsedError.entity.to ? entityListItem(error.parsedError.entity.to) : '-'}
                </div>
              </div>
            </Paper>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('Error')}
            </Typography>
            <Paper
              style={{
                padding: '15px',
                borderRadius: 4,
              }}
              variant="outlined"
            >
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: 15 }}>
                <div>
                  <Typography variant="h3" gutterBottom={true}>{t_i18n('Timestamp')}</Typography>
                  <pre><ItemCopy content={error.rawError.timestamp ?? '-'} /></pre>
                </div>
                <div>
                  <Typography variant="h3" gutterBottom={true}>{t_i18n('Message')}</Typography>
                  <pre><ItemCopy content={error.rawError.message ?? '-'} variant={'wrap'} /></pre>
                </div>
                <div>
                  <Typography variant="h3" gutterBottom={true}>{t_i18n('Source')}</Typography>
                  <pre><ItemCopy content={error.rawError.source ?? '-'} variant={'wrap'} /></pre>
                </div>
              </div>
            </Paper>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleToggleModalError} color="primary">
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ConnectorWorksErrorLine;
