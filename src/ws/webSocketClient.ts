import events from 'events';
import ws from 'ws';
import { logger } from '../common';
import { Util } from '../util';



export class WebSocketClient extends events.EventEmitter {

    /**
     *
     */
    protected _remoteAddress: string;
    public id: string;
    protected _isAuthenticated: boolean = false;
    private _checkAuthentication: NodeJS.Timeout | undefined;
    protected _rooms: Set<string> = new Set();
    public isAlive = false;
    constructor(remoteAddress: string, protected socket: ws) {
        super();
        this.isAlive = true;
        this._remoteAddress = remoteAddress;
        this.id = Util.randomNumberString(16);
        socket.on('close', async (socket: ws, code: number, reason: string) => {
            logger.info(`client disconnected from ${this._remoteAddress} with id:${this.id} code:${code} reason:${reason}`);
            await this.onClose();

        });
        socket.on('message', async (data: ws.Data) => {
            this.onMessage(data);
        })
        socket.on('pong', async () => {
            this.isAlive = true;
            await this.onPong();
        })
        //check if authentication not finished in 60 seconds
        this._checkAuthentication = setTimeout(() => {
            logger.info(`client with id:${this.id} not authenticated`);
            if (!this._isAuthenticated)
                this.close();
        }, 3000)

    }
    async onClose() {
        this.emit('close', this);
    }
    async onMessage(message: string | Buffer | ArrayBuffer | Buffer[]) {
        this.emit('message', message);
    }
    async onPong() {

    }
    async setAuthenticated() {
        this._isAuthenticated = true;
        if (this._checkAuthentication)
            clearTimeout(this._checkAuthentication);
        this._checkAuthentication = undefined;
        this.emit('authenticated', this);
        logger.info(`client id:${this.id} is authenticated`);
    }

    async send(data: any) {
        if (data) {
            let str = typeof (data) == "object" ? JSON.stringify(data) : String(data);
            return new Promise((resolve, reject) => {
                this.socket.send(str, (err) => {
                    if (err)
                        reject(err);
                    else
                        resolve('');
                });
            })

        }

    }
    async ping() {
        return new Promise((resolve, reject) => {
            this.socket.ping(undefined, undefined, (err) => {
                if (err)
                    reject(err)
                else
                    resolve(err);
            })
        })

    }
    async close() {
        if (this.socket.readyState == ws.OPEN)
            this.socket.terminate();
    }


}