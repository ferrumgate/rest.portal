



import { logger } from '../common';
import ws from 'ws';


import { Util } from "../util";
import { WebSocketClient } from "./webSocketClient";
import { RedisService } from '../service/redisService';
import { ConfigService } from '../service/configService';


export class WebSocketClientCommand extends WebSocketClient {


    constructor(private configService: ConfigService, private redisService: RedisService,
        protected remoteAddress: string, protected socket: ws) {
        super(remoteAddress, socket);

    }
    async onMessage(message: string | Buffer | ArrayBuffer | Buffer[]) {

        if (message == 'pong') {
            await this.onPong();
        } else
            if (message == 'ping') {
                await this.send('pong');
            }
            else
                if (!this._isAuthenticated)
                    await this.authenticate(message);
        super.onMessage(message);

    }

    async authenticate(data: any) {
        try {
            const input = JSON.parse(data) as { publicKey: string };
            logger.info(`client id:${this.id} is authenticating`);
            const { publicCrt: caPub } = await this.configService.getCASSLCertificate();
            if (!caPub)
                throw new Error("ca certificate public key is null");
            const result = await Util.getCertificateInfo(input.publicKey, caPub);
            if (!result.isValid || result.remainingMS < 0)
                throw new Error("cerfiticate verification failed");
            super.setAuthenticated();

        } catch (err) {
            logger.error(err);
            super.close();
        }
    }

    async onPong() {
        try {


        } catch (ignored) {
            logger.error(ignored);
        }
    }
}
