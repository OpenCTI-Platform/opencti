import React, { FunctionComponent } from 'react';
import { LocationDetails_location$key } from '@components/locations/__generated__/LocationDetails_location.graphql';
import { graphql, useFragment } from 'react-relay';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../components/i18n';
import Card from '../../../components/common/card/Card';
import Label from '../../../components/common/label/Label';

const locationDetailsFragment = graphql`
  fragment LocationDetails_location on Location {
    id
    description
  }
`;

interface LocationDetailsProps {
  locationData: LocationDetails_location$key;
}

const LocationDetails: FunctionComponent<LocationDetailsProps> = ({ locationData }) => {
  const { t_i18n } = useFormatter();
  const location = useFragment(locationDetailsFragment, locationData);

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <div>
          <Label>
            {t_i18n('Description')}
          </Label>
          <ExpandableMarkdown source={location.description} limit={300} />
        </div>
      </Card>
    </div>
  );
};

export default LocationDetails;
