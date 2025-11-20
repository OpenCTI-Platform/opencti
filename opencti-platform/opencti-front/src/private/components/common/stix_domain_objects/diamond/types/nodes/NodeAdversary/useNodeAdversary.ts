import * as R from 'ramda';
import getFilterFromEntityTypeAndNodeType from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import { emptyFilled } from '../../../../../../../../utils/String';
import { DiamondEntityEnum, DiamondNodeEnum } from '../diamondEnums';

export interface UseNodeAdversaryProps {
  data: {
    stixDomainObject: {
      entity_type: DiamondEntityEnum;
      aliases?: string[];
      attributedTo?: {
        edges: {
          node: {
            to: {
              name: string;
            };
          };
        }[];
      };
      attributedFrom?: {
        edges: {
          node: {
            from: {
              name: string;
            };
          };
        }[];
      };
      usedBy?: {
        edges: {
          node: {
            from: {
              name: string;
            };
          };
        }[];
      };
    };
    entityLink: string;
  };
}
export interface UseNodeAdversaryReturns {
  entityLink: string;
  generatedFilters: string;
  aliases?: string;
  isArsenal: boolean;
  lastAttributions: React.ReactNode;
}

export const useNodeAdversary = ({ data }: UseNodeAdversaryProps):UseNodeAdversaryReturns => {
  const { stixDomainObject, entityLink } = data;

  const isArsenal = [DiamondEntityEnum.malware, DiamondEntityEnum.tool, DiamondEntityEnum.channel].includes(stixDomainObject.entity_type);
  const isThreat = [DiamondEntityEnum.threatActorGroup, DiamondEntityEnum.threatActorIndividual, DiamondEntityEnum.intrusionSet].includes(stixDomainObject.entity_type);

  const aliases = stixDomainObject.aliases?.slice(0, 5).join(', ');

  const attributedTo = R.uniq((stixDomainObject.attributedTo?.edges ?? [])
    .map((n: { node: { to: { name: string } } }) => n?.node?.to?.name))
    .join(', ');

  const attributedFrom = R.uniq((stixDomainObject.attributedFrom?.edges ?? [])
    .map((n: { node: { from: { name: string } } }) => n?.node?.from?.name))
    .join(', ');

  const usedBy = R.uniq((stixDomainObject.usedBy?.edges ?? [])
    .map((n: { node: { from: { name: string } } }) => n?.node?.from?.name))
    .join(', ');

  let lastAttributions;
  if (isArsenal === true) {
    lastAttributions = emptyFilled(usedBy);
  } else if (isThreat === true) {
    lastAttributions = emptyFilled(attributedFrom);
  } else {
    lastAttributions = emptyFilled(attributedTo);
  }

  const generatedFilters = getFilterFromEntityTypeAndNodeType(stixDomainObject.entity_type, DiamondNodeEnum.adversary);

  return {
    entityLink,
    generatedFilters,
    aliases,
    isArsenal,
    lastAttributions,
  };
};
