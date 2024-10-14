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

export type ParsedWorkMessage = {
  isParsed: boolean,
  tabsType: 'Critical' | 'Warning' | 'Other',
  parsedError: {
    timestamp: string,
    type: string,
    reason: string,
    entityId: string,
    entityName: string,
  }
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
              {error.parsedError.entityName}
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
            <pre><ItemCopy content={error.rawError.timestamp} /></pre>
            <pre><ItemCopy content={error.rawError.message} variant={'wrap'} /></pre>
            <pre><ItemCopy content={error.rawError.source} variant={'wrap'} /></pre>
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
