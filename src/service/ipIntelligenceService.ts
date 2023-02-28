import Axios, { AxiosRequestConfig } from "axios";
import { Util } from "../util";
import { Countries } from "../model/country";
import { IpIntelligenceItem, IpIntelligenceSource } from "../model/IpIntelligence";
import { ConfigService } from "./configService";
import { RedisService } from "./redisService";




export abstract class IpIntelligenceSourceApi {

    constructor() {

    }
    abstract getType(): string;
    //abstract checkIsWorking(): Promise<any>;
    abstract query(ip: string, timeout: number): Promise<IpIntelligenceItem | null>;

}

class IPApiCom extends IpIntelligenceSourceApi {
    type: string;
    url: string;
    constructor(private apikey: string, type: string, private options: any) {
        super();
        this.type = type;
        this.url = `https://api.ipapi.com/api`;
        if (this.options.isFreePlan)
            this.url = `http://api.ipapi.com/api`;

    }
    override getType(): string {
        return this.type;
    }
    async get(ip: string, timeout = 5000) {
        let options: AxiosRequestConfig = {
            timeout: timeout,
            /* headers: {
                ApiKey: ''
            } */
        };
        const searchParams = new URLSearchParams();
        searchParams.append('access_key', this.apikey);
        if (this.options.isSecurityPlan)
            searchParams.append('security', '1');


        const url = `${this.url}/${ip}?${searchParams.toString()}`;
        const response = await Axios.get(url, options);
        const data = response.data;
        if (data.success == false)
            throw data.error;
        return data;
    }
    /* override async checkIsWorking() {

        return await this.get('1.1.1.1');
    } */
    override async query(ip: string, timeout: number) {
        const response = await this.get(ip, timeout);
        //match from our country list
        const country = Countries.find(x => x.isoCode == response.country_code);
        if (!country) return null;
        const intel: IpIntelligenceItem = {
            ip: ip,
            countryCode: country.isoCode,
            countryName: country.name,
            isCrawler: response.securiy?.is_crawler || false,
            isHosting: false,
            isProxy: response.security?.is_proxy || response.security?.is_tor || false
        }
        return intel;
    }

}



class IPDataCo extends IpIntelligenceSourceApi {
    type: string;
    url: string;
    constructor(private apikey: string, type: string, private options: any) {
        super();
        this.type = type;
        this.url = `https://api.ipdata.co`;


    }
    override getType(): string {
        return this.type;
    }
    async get(ip: string, timeout = 5000) {
        let options: AxiosRequestConfig = {
            timeout: timeout,
            /* headers: {
                ApiKey: ''
            } */
        };
        const searchParams = new URLSearchParams();
        searchParams.append('api-key', this.apikey);



        const url = `${this.url}/${ip}?${searchParams.toString()}`;
        const response = await Axios.get(url, options);
        const data = response.data;
        return data;
    }
    /* override async checkIsWorking() {

        return await this.get('1.1.1.1');
    } */
    override async query(ip: string, timeout: number) {
        const response = await this.get(ip, timeout);
        //match from our country list
        const country = Countries.find(x => x.isoCode == response.country_code);
        if (!country) return null;
        const intel: IpIntelligenceItem = {
            ip: ip,
            countryCode: country.isoCode,
            countryName: country.name,
            isCrawler: false,
            isHosting: response.threat?.is_datacenter || false,
            isProxy: response.threat?.is_proxy || response.threat?.is_tor || response.thread?.is_vpn || false
        }
        return intel;
    }

}

class IPifyOrg extends IpIntelligenceSourceApi {
    type: string;
    url: string;
    constructor(private apikey: string, type: string, private options: any) {
        super();
        this.type = type;
        this.url = `https://geo.ipify.org/api/v2/country`;
        if (options.isSecurityPlan)
            this.url = `https://geo.ipify.org/api/v2/country,city,vpn`;


    }
    override getType(): string {
        return this.type;
    }
    async get(ip: string, timeout = 5000) {
        let options: AxiosRequestConfig = {
            timeout: timeout,
            /* headers: {
                ApiKey: ''
            } */
        };
        const searchParams = new URLSearchParams();
        searchParams.append('apiKey', this.apikey);
        searchParams.append('ipAddress', ip);


        const url = `${this.url}?${searchParams.toString()}`;
        const response = await Axios.get(url, options);
        const data = response.data;
        return data;
    }
    /* override async checkIsWorking() {

        return await this.get('1.1.1.1');
    } */
    override async query(ip: string, timeout: number) {
        const response = await this.get(ip, timeout);
        //match from our country list
        const country = Countries.find(x => x.isoCode == response.location.countryCode);
        if (!country) return null;
        const intel: IpIntelligenceItem = {
            ip: ip,
            countryCode: country.isoCode,
            countryName: country.name,
            isCrawler: false,
            isHosting: false || false,
            isProxy: response.proxy?.proxy || response.proxy?.vpn || response.proxy?.tor || false
        }
        return intel;
    }

}


export class IpIntelligenceService {
    protected api: IpIntelligenceSourceApi | null = null;
    protected apiCount = -1;
    constructor(private config: ConfigService,
        private redis: RedisService) {

    }
    protected async createApi(force = false) {
        if (force || this.apiCount == -1) {
            await this.reConfigure();
        }

    }
    async reConfigure() {
        this.api = null;
        this.apiCount = -1;
        this.api = await this.getApi();
        if (this.api)
            this.apiCount = 1;
        else this.apiCount = 0;
    }


    protected async getApi(type?: string | IpIntelligenceSource) {
        let source: IpIntelligenceSource | undefined;
        if (typeof (type) == 'undefined' || typeof (type) == 'string') {
            let sources = (await this.config.getIpIntelligenceSources())
            if (typeof (type) == 'string')
                source = sources.find(x => x.type == type);//get correct element
            else
                source = sources.find(x => x);//find first element
            if (!source) {
                return null;
            }
        }
        else
            source = type;
        const checkType = source.type;
        switch (checkType) {
            case 'ipdata.co':
                return new IPDataCo(source.apiKey, source.type, {});
            case 'ipapi.com':
                return new IPApiCom(source.apiKey, source.type, { isFreePlan: source.isFreePlan, isSecurityPlan: source.isSecurityPlan });
            case 'ipify.org':
                return new IPifyOrg(source.apiKey, source.type, { isSecurityPlan: source.isSecurityPlan });
            default:
                throw new Error(`${type} not implemented yet`);
        }
    }

    async check(source: IpIntelligenceSource) {
        const api = await this.getApi(source);
        if (!api)
            throw new Error(`could not create an ip intelligence source for ${source.type}`);
        return await api.query('1.1.1.1', 3000);
    }

    async query(ip: string) {
        await this.createApi();
        if (Util.isLocalNetwork(ip)) return null;

        if (this.api) {
            //check from cache
            const item = await this.redis.get(`/ip/intelligence/${ip}`, true);
            if (item) return item as IpIntelligenceItem;
            const result = await this.api.query(ip, 3000);
            if (result) {
                await this.redis.set(`/ip/intelligence/${ip}`, result, { ttl: 6 * 60 * 60 * 1000 });//set 6 hours ttl
            }
            return result;
        }
        return null;

    }




}