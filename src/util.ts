import Axios from 'axios';
import extract from 'extract-zip';
import fs from 'fs';
import * as ipAddress from 'ip-address';
import { BigInteger } from 'jsbn';
import * as JWT from 'jsonwebtoken';
import { isIPv4 } from 'net';
import { ZipAFolder } from 'zip-a-folder';
import { logger } from './common';
import { ErrorCodes, RestfullException } from './restfullException';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import randtoken from 'rand-token';
import ip6addr from 'ip6addr';



export interface IpRange {
    start: string;
    end: string;
}


export interface NetworkDefinition {
    baseIp: string;
    mask: number;
}


export const Util = {

    /**
     * verify a jwt token with public certificate
     */
    /*verifyJwt: (token: string, key: string) => { //returns token or restfull 401
        try {
            let JWT_VERIFY_OPTIONS = { algorithms: ['RS256'] } as unknown as JWT.VerifyOptions;
            let decoded = JWT.verify(token, key, JWT_VERIFY_OPTIONS) as any;
            let currentTime = new Date().getTime();
            if (decoded.expires <= currentTime) {
                if (process.env.NODE_ENV !== 'development')
                    throw new Error('jwt expired')
            }
            return decoded;

        } catch (err) {
            logger.error(`jwt auth failed with ${token} ${err}`)
            throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'not authorized');
        }
    }, */
    /**
     * create bcyrpt hash of string
     * 
     */
    bcryptHash: (val: string) => {
        return bcrypt.hashSync(val, 10);
    },
    /**
     * compare hash of string to hash
     * @returns true or false
     */
    bcryptCompare: (val: string, hash: string) => {
        return bcrypt.compareSync(val, hash);
    },
    /**
     * creates a random token with len parameters
     */
    createRandomHash: (len: number = 16): string => {
        return randtoken.generate(len);
    },
    /**
     * creates a random string with 6 length
     */
    randomNumberString: (string_length: number = 6) => {


        var chars = "0123456789abcdefghiklmnopqrstuvwxyz";

        var randomstring = '';
        for (var i = 0; i < string_length; i++) {
            var rnum = Math.floor(Math.random() * chars.length);
            randomstring += chars.substring(rnum, rnum + 1);
        }
        return randomstring;
    },
    replaceNewLine: (val: string) => {
        return val.replace(/(\r\n|\n|\r)/gm, '\\n');
    },
    /**
     * save object to file as json
     * @param obj 
     * @param file 
     */
    saveJson: (obj: any, file: string) => {
        fs.writeFileSync(file, JSON.stringify(obj));
    },
    /**
     * load json from a file
     * @param file 
     */
    loadJson: <T>(file: string): T => {
        return JSON.parse(fs.readFileSync(file).toString()) as T;
    },
    downloadFile: async (url: string, path: string): Promise<void> => {
        const writer = fs.createWriteStream(path);

        const response = await Axios({
            url,
            method: 'GET',
            responseType: 'stream'
        })

        response.data.pipe(writer)

        await new Promise((resolve, reject) => {
            writer.on('finish', resolve)
            writer.on('error', reject)
        })

    },
    extractZipFile: async (path: string, toFolder: string): Promise<string> => {

        await extract(path, { dir: toFolder });
        return toFolder;
    },
    zipFolder: async (folder: string, topath: string): Promise<void> => {
        await ZipAFolder.zip(folder, topath);
    },
    ipToBigInteger: (ip: string): bigint => {
        if (isIPv4(ip)) {
            let big = new ipAddress.Address4(ip).bigInteger();
            return BigInt(big.toString());
        };
        return BigInt(new ipAddress.Address6(ip).bigInteger().toString());

    },

    compressIp: (ip: string): string => {
        //ip-address kutuphanesi ipv6 addreslerini compress etmiyordu
        return ip6addr.parse(ip).toString();
    },
    bigIntegerToIp: (ip: bigint): string => {

        if (ip <= BigInt(4294967295))
            return Util.compressIp(ipAddress.Address4.fromBigInteger(new BigInteger(ip.toString())).address);
        else
            return Util.compressIp(ipAddress.Address6.fromBigInteger(new BigInteger(ip.toString())).address);


    },
    ipRangeToCidr: (startIp: string, endIp: string): NetworkDefinition | null => {
        let mask = 32;
        while (mask >= 8) {
            let ip = isIPv4(startIp) ? new ipAddress.Address4(startIp + '/' + mask) : new ipAddress.Address6(startIp + '/' + mask);
            let end = isIPv4(startIp) ? new ipAddress.Address4(endIp + '/' + 32) : new ipAddress.Address6(endIp + '/' + mask);
            if (ip.startAddress().address == startIp && ip.endAddress().address == endIp)
                return { baseIp: startIp, mask: mask };
            mask--;

        }

        return null;
    },

    ipCidrToRange: (ip: string, mask: number): IpRange => {
        let iptemp = isIPv4(ip) ? new ipAddress.Address4(ip + '/' + mask) : new ipAddress.Address6(ip + '/' + mask);
        return { start: Util.compressIp(iptemp.startAddress().address), end: Util.compressIp(iptemp.endAddress().address) }
    },
    isLocalNetwork: (ip: string): boolean => {
        return ip.startsWith('10.') || ip.startsWith('172.16.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('169.254.') || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip == '::1';
    },
    findClientIpAddress: (req: any) => {
        let ip = req.get('x-real-ip');
        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('client-ip');
        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('Proxy-Client-IP');
        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('WL-Proxy-Client-IP');

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('HTTP_X_FORWARDED_FOR');

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('HTTP_X_FORWARDED');

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('HTTP_X_CLUSTER_CLIENT_IP');

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('HTTP_CLIENT_IP');

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('HTTP_FORWARDED_FOR');

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('HTTP_FORWARDED');

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('HTTP_VIA');

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.get('REMOTE_ADDR');

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.ip;

        if (!ip || ip == 'unknown' || Util.isLocalNetwork(ip))
            ip = req.connection.remoteAddress;

        if (ip && ip.substr(0, 7) == "::ffff:") {
            //logger.info(`ip is ipv4 mapped ipv6 ${ip}`);
            ip = ip.substr(7)
        }
        return ip;

    },
    /**
 * @description gets X-Forwarded-Host or host from http headers or returns `not found`
 * @param req http request
 */
    findHttpHost: (req: any): string => {
        //logger.info("http headers:" + JSON.stringify(req.headers))
        return req.get('X-Forwarded-Host') || req.get('host') || 'not found';
    },
    findHttpProtocol: (req: any): string => {
        //logger.info("http headers:" + JSON.stringify(req.headers))
        return req.protocol || 'not found';
    },
    encrypt(key: string, data: string): string {

        const keyBuffer = Buffer.from(key).slice(0, 32); //8f7403c9bb5eb04f

        const iv = Buffer.from("5d97bf41edc9285f0ed88caa9e47218f", 'hex');
        //const pass=crypto.scryptSync(key,initVector,initVector.length);
        const algoritm = 'aes-256-cbc'
        const cipher = crypto.createCipheriv(algoritm, keyBuffer, iv);
        const encrypted = Buffer.concat([cipher.update(Buffer.from(data, 'utf-8')), cipher.final()]);

        return encrypted.toString('hex');


    },

    decrypt(key: string, data: string): string {

        const keyBuffer = Buffer.from(key).slice(0, 32); //8f7403c9bb5eb04f

        const iv = Buffer.from("5d97bf41edc9285f0ed88caa9e47218f", 'hex');
        //const pass=crypto.scryptSync(key,initVector,initVector.length);
        const algoritm = 'aes-256-cbc'
        const cipher = crypto.createDecipheriv(algoritm, keyBuffer, iv);
        const decrpted = Buffer.concat([cipher.update(Buffer.from(data, 'hex')), cipher.final()]);

        let value = decrpted.toString('utf-8');
        return value;


    },

    async sleep(microseconds: number) {
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                resolve('timeout');
            }, microseconds)
        })
    },

    clone(x: any) {
        if (!x) return x;
        return JSON.parse(JSON.stringify(x));
    }








}