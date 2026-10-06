import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import {
  CitizenshipDocumentDetails_citizenshipDocument$data,
} from '@components/entities/citizenshipDocuments/__generated__/CitizenshipDocumentDetails_citizenshipDocument.graphql';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

interface CitizenshipDocumentDetailsComponentProps {
  citizenshipDocument: CitizenshipDocumentDetails_citizenshipDocument$data;
}

const CitizenshipDocumentDetailsComponent: FunctionComponent<CitizenshipDocumentDetailsComponentProps> = ({ citizenshipDocument }) => {
  const { t_i18n } = useFormatter();
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown
              source={citizenshipDocument.description}
              limit={400}
            />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Citizenship document type')}
            </Label>
            <FieldOrEmpty source={citizenshipDocument.x_opencti_citizenship_document_type}>
              <Tag
                label={citizenshipDocument.x_opencti_citizenship_document_type}
              />
            </FieldOrEmpty>
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

const CitizenshipDocumentDetails = createFragmentContainer(
  CitizenshipDocumentDetailsComponent,
  {
    citizenshipDocument: graphql`
      fragment CitizenshipDocumentDetails_citizenshipDocument on CitizenshipDocument {
        id
        description
        x_opencti_citizenship_document_type
        objectLabel {
          id
          value
          color
        }
      }
    `,
  },
);

export default CitizenshipDocumentDetails;
