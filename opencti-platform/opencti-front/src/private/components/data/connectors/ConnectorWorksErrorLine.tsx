import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import Button from '@mui/material/Button';
import React, { FunctionComponent, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import { WorkMessages } from '@components/data/connectors/ConnectorWorks';
import ItemCopy from '../../../../components/ItemCopy';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import IconButton from '@mui/material/IconButton';
import { DeleteOutlined, InfoOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { truncate } from '../../../../utils/String';

export type ParsedWorkMessage = {
  isParsed: boolean,
  level: 'Critical' | 'Warning' | 'Unclassified',
  parsedError: {
    category: string,
    message: string,
    entityId: string,
    entityName: string,
    entityType: string,
  }
  rawError: WorkMessages,
};

export type testMessage = {
  isParsed: true,
  level: 'Critical' | 'Warning' | 'Unclassified',
  parsedError: {
    category: string,
    reason: string,
    entityId: string,
    entityName: string,
    entityType: string,
  }
  rawError: WorkMessages,
} | {
  isParsed: false,
  level: 'Unclassified',
  rawError: WorkMessages,
};

interface ConnectorWorksErrorLineProps {
  error: ParsedWorkMessage;
}

const ConnectorWorksErrorLine: FunctionComponent<ConnectorWorksErrorLineProps> = ({ error }) => {
  const { t_i18n, nsdt } = useFormatter();
  const [openModalErrorDetails, setOpenModalErrorDetails] = useState<boolean>(false);

  const handleToggleModalError = () => {
    setOpenModalErrorDetails(!openModalErrorDetails);
  };

  return (
    <>
      <TableRow key={error.rawError.timestamp}>
        <TableCell>{nsdt(error.rawError.timestamp)}</TableCell>
        <TableCell>
          {error.isParsed ? (
            <a href={`https://docs.opencti.io/latest/deployment/troubleshooting/#${error.parsedError.category}`} target="_blank">{error.parsedError.category}</a>
          ) : (
            <a href={'https://docs.opencti.io/latest/deployment/troubleshooting'} target="_blank">{t_i18n('Docs')}</a>
          )}
        </TableCell>
        <TableCell>{error.isParsed ? error.parsedError.message : error.rawError.message}</TableCell>
        <TableCell>
          {error.isParsed ? (
            <a href={`/dashboard/id/${error.parsedError.entityId}`} target="_blank">{`[${error.parsedError.entityType}] ${error.parsedError.entityName}`}</a>
          ) : (
            truncate(error.rawError.source, 50)
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
        <DialogTitle>Error</DialogTitle>
        <DialogContent>
          <DialogContentText>
            <pre><ItemCopy content={error.rawError.timestamp ?? '-'} /></pre>
            <pre><ItemCopy content={error.rawError.message ?? '-'} variant={'wrap'} /></pre>
            <pre><ItemCopy content={error.rawError.source ?? '-'} variant={'wrap'} /></pre>
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
