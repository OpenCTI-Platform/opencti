import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import Button from '@mui/material/Button';
import React, { FunctionComponent, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import ItemCopy from '../../../../components/ItemCopy';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';

type WorkMessages = {
  message: string,
  sequence: number,
  source: string,
  timestamp: any,
}

type ParsedWorkMessage = {
  isParsed: boolean,
  parsedError: {
    timestamp: any,
    type: string,
    reason: string,
    entityId: any,
  }
  rawError: WorkMessages,
}

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
      {error.isParsed ? (
        <TableRow key={error.parsedError.timestamp} hover onClick={handleToggleModalError}>
          <TableCell>{nsdt(error.parsedError.timestamp)}</TableCell>
          <TableCell>
            <Button href={`https://docs.opencti.io/latest/deployment/troubleshooting/#${error.parsedError.type}`} target="_blank" onClick={(event) => event.stopPropagation()}>
              {error.parsedError.type}
            </Button>
          </TableCell>
          <TableCell>{error.parsedError.reason}</TableCell>
          <TableCell>
            <Button href={`/dashboard/id/${error.parsedError.entityId}`} target="_blank" onClick={(event) => event.stopPropagation()}>
              {error.parsedError.entityId}
            </Button>
          </TableCell>
        </TableRow>
      ) : (
        <TableRow key={error.parsedError.timestamp} hover onClick={handleToggleModalError}>
          <TableCell>{nsdt(error.rawError.timestamp)}</TableCell>
          <TableCell>
            <Button href={'https://docs.opencti.io/latest/deployment/troubleshooting'} target="_blank" onClick={(event) => event.stopPropagation()}>
              {t_i18n('Docs')}
            </Button>
          </TableCell>
          <TableCell>{error.rawError.message}</TableCell>
          <TableCell>{error.rawError.source}</TableCell>
        </TableRow>
      )}
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={openModalErrorDetails}
        TransitionComponent={Transition}
        onClose={handleToggleModalError}
      >
        <DialogTitle>Error</DialogTitle>
        <DialogContent>
          <DialogContentText>
            <pre><ItemCopy content={error.rawError.timestamp} variant={'inline'} /></pre>
            <pre><ItemCopy content={error.rawError.message} variant={'inline'} /></pre>
            <pre><ItemCopy content={error.rawError.source} variant={'inline'} /></pre>
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
