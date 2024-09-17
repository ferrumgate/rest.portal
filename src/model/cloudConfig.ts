export interface CloudConfig {
    ferrumCloudId: string;
    ferrumCloudUrl: string;
    ferrumCloudToken: string;

    //public ip of the cloud server
    ferrumCloudIp: string;
    //public reachable port of the cloud server
    ferrumCloudPort: string;
    redisPass: string;
    redisIntelPass: string;
    encryptKey: string;
    esUser: string;
    esPass: string;
    esIntelUser: string;
    esIntelPass: string;
    clusterNodePublicKey: string;

}

export interface CloudWorker {
    peerw: string;
}
