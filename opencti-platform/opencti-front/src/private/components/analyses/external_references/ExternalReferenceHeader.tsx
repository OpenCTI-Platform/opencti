import React, { FunctionComponent, ReactElement } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { truncate } from '../../../../utils/String';
import Security from '../../../../utils/Security';
import { ExternalReferenceHeader_externalReference$data } from './__generated__/ExternalReferenceHeader_externalReference.graphql';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
}));

interface ExternalReferenceHeaderComponentProps {
  externalReference: ExternalReferenceHeader_externalReference$data;
  PopoverComponent: ReactElement<{ id: string }>;
  EditComponent?: React.JSX.Element | boolean;
}

const ExternalReferenceHeaderComponent: FunctionComponent<ExternalReferenceHeaderComponentProps> = ({ externalReference, PopoverComponent, EditComponent }) => {
  const classes = useStyles();

  return (
    <div
      style={{
        display: 'inline-flex',
        justifyContent: 'space-between',
        width: '100%',
      }}
    >
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {truncate(externalReference.source_name, 80)}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <div className={classes.popover}>
            {React.cloneElement(PopoverComponent, { id: externalReference.id })}
          </div>
        </Security>
        <div className="clearfix" />
      </div>
      {EditComponent}
    </div>
  );
};

const ExternalReferenceHeader = createFragmentContainer(
  ExternalReferenceHeaderComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceHeader_externalReference on ExternalReference {
        id
        source_name
        description
      }
    `,
  },
);

export default ExternalReferenceHeader;
