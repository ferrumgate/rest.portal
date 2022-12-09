import { Util } from "../../util";
import { logger } from "../../common";
import { ConfigEvent } from "../../model/config";
import { ConfigService } from "../configService";
import { RedisService } from "../redisService";
import { RedisWatcher } from "./redisWatcher";
import { EventEmitter } from "stream";

const { setIntervalAsync, clearIntervalAsync } = require('set-interval-async');

/**
 * @summary publish config service events to redis pub/sub
 */
export class ConfigReplicator {
    /**
     *
     */

    private trimInterval: any;
    private fullReplicationInterval: any;
    private isFullReplicationFinished = false;
    private lastFullReplicationTime = 0;
    private lastReplicationWriteNumber = 0;
    private replicationReadPos = '$';
    public encKey;
    constructor(private configService: ConfigService,
        private redisWatcher: RedisWatcher,
        private redisService: RedisService,
        private redisStreamService: RedisService) {
        this.encKey = this.configService.getEncKey();
    }


    async replicationWrite() {
        try {
            if (!this.redisWatcher.isMaster) {
                logger.warn('config replicator redis is not master yet, skip replication write');
                return;
            }
            if (this.isFullReplicationFinished &&
                (new Date().getTime() - this.lastFullReplicationTime) < 3 * 60 * 60 * 1000)//every 3 hours write again
                return;
            logger.info("config replicator making full replication");
            const conf = this.configService.saveConfigToString();
            const data: ConfigEvent = { path: '.replication', type: 'saved', data: conf }
            const json = JSON.stringify(data);
            const enc = Util.encrypt(this.encKey, json);
            this.lastReplicationWriteNumber++;
            await this.redisService.xadd('/replication/config', { data: enc }, `${new Date().getTime()}-${this.lastReplicationWriteNumber}`);
            this.isFullReplicationFinished = true;
            this.lastFullReplicationTime = new Date().getTime();

        } catch (err) {
            logger.error(err)
        }
    }
    async replicationTrim(start?: string) {
        try {
            if (!this.redisWatcher.isMaster) {
                logger.warn('config replicator redis is not master yet, skip replication trim');
                return;
            }
            logger.info("config replicator trimming /replication/config")
            await this.redisService.xtrim('/replication/config', start || (new Date().getTime() - 1 * 60 * 60 * 1000).toString());

        } catch (err) {
            logger.error(err);
        }
    }
    //we did not implemented yet, we are thinking over this
    async replicationRead() {

        try {
            if (this.redisWatcher.isMaster) {
                logger.warn("config replicator redis is master skip replication read")
                return;
            }
            while (true) {
                const items = await this.redisStreamService.xread(`/replication/config`, 10000, this.replicationReadPos, 5000);
                if (items && items.length) {
                    for (const item of items) {
                        this.replicationReadPos = item.xreadPos;
                        const data = JSON.parse(item) as { data: string };
                        const decData = Util.decrypt(this.encKey, data.data);
                        const event = JSON.parse(decData) as ConfigEvent;
                        if (event.path == '.replication') {
                            this.configService.config = JSON.parse(event.data);
                        }



                    }
                } else
                    break;

            }
        } catch (err) {
            logger.error(err);
            await Util.sleep(1000);
        }

    }
    async start() {


        this.configService.events.on('changed', async (data: ConfigEvent) => {

            try {
                if (!this.redisWatcher.isMaster) {
                    logger.warn('redis is not master yet');
                    return;
                }
                logger.info(`config replicator config changed event ${data.type}: ${data.path}`);
                /* if (!this.isFullReplicationFinished)//if not full replication succeeded
                    await this.replicationWrite();
                const json = JSON.stringify(data);
                const enc = Util.encrypt(this.encKey, json);
                //const b64 = Buffer.from(json).toString('base64');
                this.lastReplicationWriteNumber++;
                await this.redisService.xadd(`/replication/config`, { data: enc }, `${new Date().getTime()}-${this.lastReplicationWriteNumber}`); */
                //this.configService.events.emit('configChanged', data);

            } catch (err) {
                logger.error(err);
            }
        })


        /*  await this.replicationTrim();
         this.trimInterval = setIntervalAsync(async () => {
             await this.replicationTrim();
         }, 1 * 60 * 60 * 1000);
         await this.replicationWrite();
         this.fullReplicationInterval = setIntervalAsync(async () => {
             await this.replicationWrite();
         }, 15 * 1000); */
    }
    async stop() {

        if (this.trimInterval)
            clearIntervalAsync(this.trimInterval);
        this.trimInterval = null;
        if (this.fullReplicationInterval)
            clearIntervalAsync(this.fullReplicationInterval)
        this.fullReplicationInterval = null;

    }
}