import { logger } from "../common";
import { ClientDevicePosture, DeviceLog } from "../model/device";
import { Network } from "../model/network";
import { User } from "../model/user";
import { Util } from "../util";
import { ConfigService } from "./configService";
import { ESService, SearchDeviceLogsRequest } from "./esService";
import { RedisService } from "./redisService";

const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');
/**
 * 
 */
export class DeviceService {


    trimInterval: any;
    constructor(private config: ConfigService, private redisService: RedisService, private redisLocalService: RedisService, private esService: ESService) {
        this.trimInterval = setIntervalAsync(async () => {
            await this.trimStream();
        }, 1 * 60 * 60 * 1000)
    }

    async saveDevicePosture(item: ClientDevicePosture) {
        const key = `/device/posture/id/${item.clientId}`;
        await this.redisService.set(key, item, { ttl: 5 * 60 * 1000 });
    }
    async getDevicePosture(id: string) {
        const key = `/device/posture/id/${id}`;
        return await this.redisService.get(key, true) as ClientDevicePosture;
    }
    async aliveDevicePosture(id: string, timeInMS?: number) {
        const key = `/device/posture/id/${id}`;
        await this.redisService.expire(key, timeInMS || 5 * 60 * 1000);
    }
    async convertDevicePostureToDeviceLog(item: ClientDevicePosture, user?: User, network?: Network) {
        let device: DeviceLog = {
            id: item.clientId,
            clientVersion: item.clientVersion || '',
            clientSha256: item.clientSha256 || '',
            insertDate: new Date().toISOString(),
            hostname: item.hostname,
            osName: item.os.name || '',
            osVersion: item.os.version || '',
            macs: item.macs?.join(',') || '',
            serial: item.serial.value || '',
            platform: item.platform,
            userId: user?.id || '',
            username: user?.username || '',
            networkdId: network?.id,
            networkName: network?.name,
            hasEncryptedDisc: item.encryptedDiscs.find(x => x.isEncrypted) ? true : false,
            hasFirewall: item.firewalls.find(x => x.isEnabled) ? true : false,
            hasAntivirus: item.antiviruses.find(x => x.isEnabled) ? true : false,
            isHealthy: true

        }
        return device;
    }
    async save(act: DeviceLog) {
        const base64 = Util.jencode(act).toString('base64url');// Buffer.from(JSON.stringify(act)).toString('base64url')
        await this.redisLocalService.xadd('/logs/device', { val: base64, type: 'b64' });
    }



    async trimStream(min?: string) {
        try {
            await this.redisLocalService.xtrim('/logs/device', min || (new Date().getTime() - 1 * 60 * 60 * 1000).toString());

        } catch (err) {
            logger.error(err);
        }
    }
    /**
     * for testing we need this
     */
    async stop() {
        if (this.trimInterval)
            clearIntervalAsync(this.trimInterval);
        this.trimInterval = null;
    }

    async search(req: SearchDeviceLogsRequest) {
        return await this.esService.searchDeviceLogs(req);
    }

}