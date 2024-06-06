import express from "express";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AuthSession } from "../model/authSession";
import { CloudConfig, CloudWorker } from "../model/cloudConfig";
import { User } from "../model/user";
import { AppService } from "../service/appService";
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import { authorizeAsAdmin } from "./commonApi";
import { Util } from "../util";
import Axios, { AxiosRequestConfig } from 'axios';
import { RestfullException } from "../restfullException";
import { ErrorCodes } from "../restfullException";
import fsp from "fs/promises";
import fs from "fs";

/////////////////////////////////  cloud //////////////////////////////////
export const routerCloudAuthenticated = express.Router();

routerCloudAuthenticated.get('/config',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`get cloud config`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const ferrumCloudId = await configService.getFerrumCloudId();
        const ferrumCloudUrl = await configService.getFerrumCloudUrl();
        const ferrumCloudToken = await configService.getFerrumCloudToken();
        const ferrumCloudHostnameOrIp = await configService.getFerrumCloudIp();
        const ferrumCloudPort = await configService.getFerrumCloudPort();
        // if this is not a cloud server, return empty
        if (ferrumCloudId === '' || ferrumCloudUrl === '' || ferrumCloudToken === '' || ferrumCloudHostnameOrIp === '' || ferrumCloudPort === '') {
            return res.status(200).json({});
        }

        const encryptKey = await configService.getEncryptKey();
        const redisPass = await configService.getRedisPass();
        const redisIntelPass = await configService.getRedisIntelPass();
        const esUser = await configService.getEsUser();
        const esPass = await configService.getEsPass();
        const esIntelUser = await configService.getEsIntelUser();
        const esIntelPass = await configService.getEsIntelPass();
        const clusterNodePublicKey = await configService.getClusterNodePublicKey();

        //try 3 time to get ip from hostname
        let ferrumCloudIp: string = '';
        let tryCounter = 3;
        while (tryCounter) {
            try {
                ferrumCloudIp = await Util.resolveHostname(ferrumCloudHostnameOrIp) || '';
                if (ferrumCloudIp) {
                    break;
                }

            } catch (ignore) {
                logger.error(`failed to resolve hostname ${ferrumCloudHostnameOrIp}, retrying...`);
                await Util.sleep(10);
            }
            tryCounter--;
        }

        let cloudConfig: CloudConfig = {
            ferrumCloudId: ferrumCloudId,
            ferrumCloudUrl: ferrumCloudUrl,
            ferrumCloudToken: ferrumCloudToken,
            ferrumCloudIp: ferrumCloudIp,
            ferrumCloudPort: ferrumCloudPort,
            encryptKey: encryptKey,
            redisPass: redisPass,
            redisIntelPass: redisIntelPass,
            esIntelUser: esIntelUser,
            esIntelPass: esIntelPass,
            esUser: esUser,
            esPass: esPass,
            clusterNodePublicKey: clusterNodePublicKey,

        };
        return res.status(200).json(cloudConfig);

    }))

routerCloudAuthenticated.get('/worker',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`get cloud workers`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const ferrumCloudId = await configService.getFerrumCloudId();
        const ferrumCloudUrl = await configService.getFerrumCloudUrl();
        const ferrumCloudToken = await configService.getFerrumCloudToken();
        // if this is not a cloud server, return empty
        if (ferrumCloudId === '' || ferrumCloudUrl === '' || ferrumCloudToken === '') {
            return res.status(200).json({});
        }
        const workers = await getCloudWorkers(ferrumCloudId, ferrumCloudUrl, ferrumCloudToken);
        return res.status(200).json(workers);

    }))


routerCloudAuthenticated.post('/worker',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        logger.info(`save cloud workers`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const cloudWorkers: CloudWorker[] = req.body.workers;
        if (!cloudWorkers)
            throw new RestfullException(500, ErrorCodes.ErrInputNullOrUndefined, ErrorCodes.ErrInputNullOrUndefined, 'invalid request')
        const ferrumCloudId = await configService.getFerrumCloudId();
        const ferrumCloudUrl = await configService.getFerrumCloudUrl();
        const ferrumCloudToken = await configService.getFerrumCloudToken();
        // if this is not a cloud server, return empty
        if (ferrumCloudId === '' || ferrumCloudUrl === '' || ferrumCloudToken === '') {
            return res.status(200).json({});
        }
        const workers = await saveCloudWorkers(ferrumCloudId, ferrumCloudUrl, ferrumCloudToken, cloudWorkers);

        return res.status(200).json(workers);

    }))


async function getCloudWorkers(ferrumCloudId: string, ferrumCloudUrl: string, ferrumCloudToken: string): Promise<any> {

    let options: AxiosRequestConfig = {
        timeout: 15 * 1000,
        headers: {
            Authorization: `${ferrumCloudToken}`,
            FerrumCloudId: `${ferrumCloudId}`
        }
    };
    const verificationURL = `${ferrumCloudUrl}/api/cloud/worker`

    const response = await Axios.get(verificationURL, options);
    return response.data as { items: CloudWorker[] };
    /* if (fs.existsSync('/tmp/cloudWorkers.json')) {
        return JSON.parse(await fsp.readFile('/tmp/cloudWorkers.json', 'utf-8'));
    } 
    return [];*/
}

async function saveCloudWorkers(ferrumCloudId: string, ferrumCloudUrl: string, ferrumCloudToken: string, cloudWorkers: CloudWorker[]): Promise<any> {

    let options: AxiosRequestConfig = {
        timeout: 15 * 1000,
        headers: {
            Authorization: `${ferrumCloudToken}`,
            FerrumCloudId: `${ferrumCloudId}`
        }
    };
    const verificationURL = `${ferrumCloudUrl}/api/cloud/worker`

    const response = await Axios.post(verificationURL, { workers: cloudWorkers }, options);
    return response.data;
    //await fsp.writeFile('/tmp/cloudWorkers.json', JSON.stringify(cloudWorkers));
}