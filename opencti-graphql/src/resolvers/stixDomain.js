import { pipe, split, join, map } from 'ramda';

const capitalizeFirstLetter = (word) => word.charAt(0).toUpperCase() + word.slice(1)

const stixDomainResolvers = {
  StixDomain: {
    __resolveType(obj) {
      if( obj.type ) {
        return pipe(
          split('-'),
          map(n => capitalizeFirstLetter(n)),
          join()
        )(obj.type);
      }
      return 'ExternalReference';
    }
  }
};

export default stixDomainResolvers;
