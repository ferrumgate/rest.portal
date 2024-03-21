import { promise } from 'ping';

/**
 * @summary ping functionality
 */
export class PingService {
    async ping(host: string, maxCount: number, maxSeconds: number) {
        return await promise.probe(host, { min_reply: maxCount, deadline: maxSeconds });
    }
}