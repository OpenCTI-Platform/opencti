import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import Button from '@common/button/Button';
import React, { FunctionComponent, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import IconButton from '@common/button/IconButton';
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
  const truncateLimit = 60;

  const handleToggleModalError = () => {
    setOpenModalErrorDetails(!openModalErrorDetails);
  };

  if (!error.rawError) {
    return null;
  }

  const displayEntityOrId = (entity: ResolvedEntity, isCopyable = false) => {
    const name = entity.representative?.main;

    const displayStandardId = (isCopyable ? (
      <pre><ItemCopy content={entity.standard_id ?? ''} variant="wrap" /></pre>
    ) : (
      <div>{entity.standard_id}</div>
    ));

    return entity.entity_type ? (
      <Tooltip title={name}>
        <a href={`/dashboard/id/${entity.id}`} target="_blank" rel="noreferrer">
          [{entity.entity_type}] {truncate(name, truncateLimit)}
        </a>
      </Tooltip>
    ) : displayStandardId;
  };

  return (
    <>
      <TableRow key={error.rawError.timestamp}>
        <TableCell>{nsdt(error.rawError.timestamp)}</TableCell>
        <TableCell>
          {error.isParsed && error.parsedError.doc_code ? (
            <a href={`https://docs.opencti.io/latest/deployment/troubleshooting/#${error.parsedError.doc_code.toLowerCase()}`} target="_blank" rel="noreferrer">{error.parsedError.doc_code}</a>
          ) : (
            <a href="https://docs.opencti.io/latest/deployment/troubleshooting" target="_blank" rel="noreferrer">{t_i18n('Unknown')}</a>
          )}
        </TableCell>
        <TableCell>{error.isParsed ? error.parsedError.message : error.rawError.message ?? '-'}</TableCell>
        <TableCell>
          {error.isParsed ? (
            displayEntityOrId(error.parsedError.entity)
          ) : (
            <Tooltip title={t_i18n('Click on details to see more information')}>
              {truncate(error.rawError.source ?? '-', truncateLimit)}
            </Tooltip>
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
        slotProps={{ paper: { elevation: 1 } }}
        open={openModalErrorDetails}
        slots={{ transition: Transition }}
        onClose={handleToggleModalError}
      >
        <DialogTitle>{t_i18n('Details')}</DialogTitle>
        <DialogContent sx={{ minWidth: '500px' }}>
          <DialogContentText>
            {error.isParsed && (
              <>
                <Typography variant="h4" gutterBottom={true}>{t_i18n('Source')}</Typography>
                <Paper
                  style={{ padding: '15px', borderRadius: 4, marginBottom: '15px' }}
                  variant="outlined"
                >
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: 15 }}>
                    <div>
                      <Typography variant="h3" gutterBottom={true}>{t_i18n('Entity')}</Typography>
                      {displayEntityOrId(error.parsedError.entity, true)}
                    </div>
                    {error.parsedError.entity.from && (
                      <div>
                        <Typography variant="h3" gutterBottom={true}>{t_i18n('From')}</Typography>
                        {displayEntityOrId(error.parsedError.entity.from, true)}
                      </div>
                    )}
                    {error.parsedError.entity.to && (
                      <div>
                        <Typography variant="h3" gutterBottom={true}>{t_i18n('To')}</Typography>
                        {displayEntityOrId(error.parsedError.entity.to, true)}
                      </div>
                    )}
                  </div>
                </Paper>
              </>
            )}
            <Typography variant="h4" gutterBottom={true}>{t_i18n('Error')}</Typography>
            <Paper
              style={{ padding: '15px', borderRadius: 4 }}
              variant="outlined"
            >
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: 15 }}>
                <div>
                  <Typography variant="h3" gutterBottom={true}>{t_i18n('Timestamp')}</Typography>
                  <pre><ItemCopy content={error.rawError.timestamp ?? '-'} /></pre>
                </div>
                <div>
                  <Typography variant="h3" gutterBottom={true}>{t_i18n('Message')}</Typography>
                  <pre><ItemCopy content={error.rawError.message ?? '-'} variant="wrap" /></pre>
                </div>
                <div>
                  <Typography variant="h3" gutterBottom={true}>{t_i18n('Source')}</Typography>
                  <pre><ItemCopy content={error.rawError.source ?? '-'} variant="wrap" /></pre>
                </div>
              </div>
            </Paper>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleToggleModalError}>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ConnectorWorksErrorLine;
