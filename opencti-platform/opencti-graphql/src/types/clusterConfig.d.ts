export type ClusterConfig = {
  platform_id: string
  managers: {
    id: string,
    enable: boolean,
    running: boolean
  }[]
};
