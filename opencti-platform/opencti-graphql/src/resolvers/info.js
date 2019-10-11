import getInfo from '../domain/info';

const infoResolvers = {
  Query: {
    info: () => getInfo()
  }
};

export default infoResolvers;
