import NodeCache from "node-cache";
import { ConfigWatch } from "../model/config";
import { RPath } from "../model/config";
import { AuthenticationRule, AuthorizationRule, WatchItem } from "../lib";
import { Group } from "../model/group";
import { Gateway } from "../model/network";
import { Network } from "../model/network";
import { Service } from "../model/service";
import { User } from "../model/user";
import { ItemWithId, RedisConfigWatchService } from "./redisConfigWatchService";
import { SSLCertificate } from "../model/sslCertificate";

class NodeCacheForThis extends NodeCache {
    override get<T>(key: string): T | undefined {
        return super.get<T>(key);
    }

    override set<T>(key: string, value: T): boolean {
        return super.set(key, value);
    }

}

/**
 * @summary cached version for policy service
 * we need super fast searching in policy service
 */
export class RedisConfigWatchCachedService extends RedisConfigWatchService {
    protected nodeCache = new NodeCacheForThis(
        {
            deleteOnExpire: false, stdTTL: 0, useClones: false
        }
    )
    override async fillFromRedis(readyEvent = true): Promise<void> {
        if (this.isFilled) return;
        await super.fillFromRedis(false);
        this.config.networks.forEach(x => this.nodeCache.set(x.id, x));
        this.config.gateways.forEach(x => this.nodeCache.set(x.id, x));
        this.config.users.forEach(x => this.nodeCache.set(x.id, x));
        this.config.groups.forEach(x => this.nodeCache.set(x.id, x));
        this.config.services.forEach(x => this.nodeCache.set(x.id, x));
        this.config.authorizationPolicy.rules.forEach(x => this.nodeCache.set(x.id, x));
        this.config.authenticationPolicy.rules.forEach(x => this.nodeCache.set(x.id, x));
        this.isFilled = true;
        this.events.emit('ready');

    }

    override async processArray(arr: ItemWithId[], path: RPath, item: ConfigWatch<any>, id?: string | undefined): Promise<void> {
        await super.processArray(arr, path, item, id);
        if (item.type == 'del' && id) {
            this.nodeCache.del(id);
        }
        if (item.type == 'put' && id) {
            this.nodeCache.set(id, item.val);
        }
    }

    override async getUserById(id: string): Promise<User | undefined> {
        return await this.nodeCache.get(id);
    }
    override async getNetwork(id: string): Promise<Network | undefined> {
        return await this.nodeCache.get(id);
    }
    override async getGateway(id: string): Promise<Gateway | undefined> {
        return await this.nodeCache.get(id);
    }
    override async getService(id: string): Promise<Service | undefined> {
        return await this.nodeCache.get(id);
    }
    override async getGroup(id: string): Promise<Group | undefined> {
        return await this.nodeCache.get(id);
    }
    override async getAuthorizationPolicyRule(id: string): Promise<AuthorizationRule | undefined> {
        return await this.nodeCache.get(id);
    }
    override async getAuthenticationPolicyRule(id: string): Promise<AuthenticationRule | undefined> {
        return await this.nodeCache.get(id);
    }




    override async processConfigChanged(watch: WatchItem<ConfigWatch<any>>) {
        if (watch.val.path.includes('authorizationPolicy')) {
            let sortMap = new Map();
            this.config.authorizationPolicy.rulesOrder.forEach((val, index) => {
                sortMap.set(val, index);
            })
            this.config.authorizationPolicy.rules.sort((a, b) => {
                return (sortMap.get(a) || 0) - (sortMap.get(b) || 0)
            })
        }
        if (watch.val.path.includes('authenticationPolicy')) {
            let sortMap = new Map();
            this.config.authenticationPolicy.rulesOrder.forEach((val, index) => {
                sortMap.set(val, index);
            })
            this.config.authenticationPolicy.rules.sort((a, b) => {
                return (sortMap.get(a) || 0) - (sortMap.get(b) || 0)
            })
        }

    }



}