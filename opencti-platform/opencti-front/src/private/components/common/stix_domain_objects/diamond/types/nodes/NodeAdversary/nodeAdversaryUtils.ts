import * as R from 'ramda';
import getFilterFromEntityTypeAndNodeType from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import { StixDomainObjectDiamond_data$data } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectDiamond_data.graphql';
import { emptyFilled } from '../../../../../../../../utils/String';
import { DiamondEntityEnum, DiamondNodeEnum } from '../diamondEnums';

export type StixDomainObjectFromDiamond = StixDomainObjectDiamond_data$data['stixDomainObject'];

export interface NodeAdversaryUtilsProps {
  data: {
    stixDomainObject: StixDomainObjectFromDiamond;
    entityLink: string;
  };
}
export interface NodeAdversaryUtilsReturns {
  entityLink: string;
  generatedFilters: string;
  aliases?: string;
  isArsenal: boolean;
  lastAttributions: React.ReactNode;
}

export const nodeAdversaryUtils = ({ data }: NodeAdversaryUtilsProps):NodeAdversaryUtilsReturns => {
  const { stixDomainObject, entityLink } = data;

  if (!stixDomainObject) {
    return {
      entityLink,
      generatedFilters: '',
      aliases: undefined,
      isArsenal: false,
      lastAttributions: '',
    };
  }

  const isArsenal = [DiamondEntityEnum.malware, DiamondEntityEnum.tool, DiamondEntityEnum.channel].includes(stixDomainObject.entity_type as DiamondEntityEnum);
  const isThreat = [DiamondEntityEnum.threatActorGroup, DiamondEntityEnum.threatActorIndividual, DiamondEntityEnum.intrusionSet]
    .includes(stixDomainObject.entity_type as DiamondEntityEnum);

  const aliases = stixDomainObject.aliases?.slice(0, 5).join(', ');

  const attributedTo = R.uniq((stixDomainObject.attributedTo?.edges ?? [])
    .map((n) => n?.node?.to?.name))
    .join(', ');

  const attributedFrom = R.uniq((stixDomainObject.attributedFrom?.edges ?? [])
    .map((n) => n?.node?.from?.name))
    .join(', ');

  const usedBy = R.uniq((stixDomainObject.usedBy?.edges ?? [])
    .map((n) => n?.node?.from?.name))
    .join(', ');

  let lastAttributions;
  if (isArsenal === true) {
    lastAttributions = emptyFilled(usedBy);
  } else if (isThreat === true) {
    lastAttributions = emptyFilled(attributedFrom);
  } else {
    lastAttributions = emptyFilled(attributedTo);
  }

  const generatedFilters = getFilterFromEntityTypeAndNodeType(stixDomainObject.entity_type as DiamondEntityEnum, DiamondNodeEnum.adversary);

  return {
    entityLink,
    generatedFilters,
    aliases,
    isArsenal,
    lastAttributions,
  };
};
