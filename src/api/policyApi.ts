import express from "express";
import { ErrorCodes, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";
import { authorize, authorizeAsAdmin } from "./commonApi";
import { cloneGroup, Group } from "../model/group";
import { AuthenticationRule, cloneAuthenticationRule } from "../model/authenticationPolicy";
import { cloneAuthenticatonProfile } from "../model/authenticationProfile";
import { AuthorizationRule } from "../model/authorizationPolicy";
import { cloneAuthorizationRule } from "../model/authorizationPolicy";




/////////////////////////////////  authentication policy //////////////////////////////////
export const routerAuthenticationPolicyAuthenticated = express.Router();


routerAuthenticationPolicyAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting authenticatoin policy`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const policy = await configService.getAuthenticationPolicy();
        if (!policy) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no policy');


        return res.status(200).json(policy);

    }));



routerAuthenticationPolicyAuthenticated.get('/rule/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting authentication policy rule with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const rule = await configService.getAuthenticationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no rule');

        return res.status(200).json(rule);

    }))



routerAuthenticationPolicyAuthenticated.delete('/rule/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`delete authentication rule with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const rule = await configService.getAuthenticationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no rule');

        await configService.deleteAuthenticationPolicyRule(rule.id);
        await configService.updateAuthenticationPolicyUpdateTime();
        //TODO audit
        return res.status(200).json({});

    }))

routerAuthenticationPolicyAuthenticated.put('/rule/pos/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");
        const input = req.body as { previous: string, current: string };
        logger.info(`changing authentication policy rule pos with id:${id} to ${input}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        await inputService.checkIsNumber(input.previous);
        await inputService.checkIsNumber(input.current);
        const rule = await configService.getAuthenticationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no rule');


        const previous = Number(input.previous);
        const current = Number(input.current);
        await configService.updateAuthenticationRulePos(rule.id, previous, current);
        await configService.updateAuthenticationPolicyUpdateTime();
        // TODO audit here
        return res.status(200).json(rule);

    }))



routerAuthenticationPolicyAuthenticated.put('/rule',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as AuthenticationRule;
        logger.info(`changing authentication policy rule with id:${input.id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        await inputService.checkNotEmpty(input.id);
        const rule = await configService.getAuthenticationPolicyRule(input.id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no rule');

        await inputService.checkNotEmpty(input.name);
        await inputService.checkNotEmpty(input.action);
        await inputService.checkNotEmpty(input.networkId);
        await inputService.checkIfExists(input.profile);

        const safe = cloneAuthenticationRule(input);
        //copy original one
        await configService.saveAuthenticationPolicyRule(safe);
        await configService.updateAuthenticationPolicyUpdateTime();
        // TODO audit here
        return res.status(200).json(safe);

    }))

routerAuthenticationPolicyAuthenticated.post('/rule',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as AuthenticationRule;
        logger.info(`save authentication policy rule with name ${input.name}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        await inputService.checkIfNotExits(input.id);


        await inputService.checkNotEmpty(input.name);
        await inputService.checkNotEmpty(input.action);
        await inputService.checkNotEmpty(input.networkId);
        await inputService.checkIfExists(input.profile);
        input.id = Util.randomNumberString();
        const safe = cloneAuthenticationRule(input);
        //copy original one
        await configService.saveAuthenticationPolicyRule(safe);
        await configService.updateAuthenticationPolicyUpdateTime();
        // TODO audit here
        return res.status(200).json(safe);

    }))


/////////////////////////////////  authorization policy //////////////////////////////////
export const routerAuthorizationPolicyAuthenticated = express.Router();


routerAuthorizationPolicyAuthenticated.get('/',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {

        logger.info(`getting authorization policy`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const policy = await configService.getAuthorizationPolicy();
        if (!policy) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no policy');


        return res.status(200).json(policy);

    }));



routerAuthorizationPolicyAuthenticated.get('/rule/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting authorization policy rule with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const rule = await configService.getAuthorizationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no rule');

        return res.status(200).json(rule);

    }))



routerAuthorizationPolicyAuthenticated.delete('/rule/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`delete authorization rule with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const rule = await configService.getAuthorizationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no rule');

        await configService.deleteAuthorizationPolicyRule(rule.id);
        await configService.updateAuthorizationPolicyUpdateTime();
        //TODO audit
        return res.status(200).json({});

    }))

routerAuthorizationPolicyAuthenticated.put('/rule/pos/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, "id is absent");
        const input = req.body as { previous: string, current: string };
        logger.info(`changing authorization policy rule pos with id:${id} to ${input}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        await inputService.checkIsNumber(input.previous);
        await inputService.checkIsNumber(input.current);
        const rule = await configService.getAuthorizationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no rule');


        const previous = Number(input.previous);
        const current = Number(input.current);
        await configService.updateAuthorizationRulePos(rule.id, previous, current);
        await configService.updateAuthorizationPolicyUpdateTime();
        // TODO audit here
        return res.status(200).json(rule);

    }))



routerAuthorizationPolicyAuthenticated.put('/rule',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as AuthorizationRule;
        logger.info(`changing authorization policy rule with id:${input.id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        await inputService.checkNotEmpty(input.id);
        const rule = await configService.getAuthorizationPolicyRule(input.id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, 'no rule');

        await inputService.checkNotEmpty(input.name);
        await inputService.checkNotEmpty(input.action);
        await inputService.checkNotEmpty(input.networkId);
        await inputService.checkIfExists(input.profile);

        const safe = cloneAuthorizationRule(input);
        //copy original one
        await configService.saveAuthorizationPolicyRule(safe);
        await configService.updateAuthorizationPolicyUpdateTime();
        // TODO audit here
        return res.status(200).json(safe);

    }))

routerAuthorizationPolicyAuthenticated.post('/rule',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as AuthorizationRule;
        logger.info(`save authorization policy rule with name ${input.name}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;

        await inputService.checkIfNotExits(input.id);


        await inputService.checkNotEmpty(input.name);
        await inputService.checkNotEmpty(input.action);
        await inputService.checkNotEmpty(input.networkId);
        await inputService.checkIfExists(input.profile);
        input.id = Util.randomNumberString();
        const safe = cloneAuthorizationRule(input);
        //copy original one
        await configService.saveAuthorizationPolicyRule(safe);
        await configService.updateAuthorizationPolicyUpdateTime();
        // TODO audit here
        return res.status(200).json(safe);

    }))






