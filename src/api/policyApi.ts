import express from "express";
import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { asyncHandler, asyncHandlerWithArgs, logger } from "../common";
import { AppService } from "../service/appService";
import { User } from "../model/user";
import { Util } from "../util";
import fs from 'fs';
import { passportAuthenticate, passportInit } from "./auth/passportInit";
import passport from "passport";
import { ConfigService } from "../service/configService";
import { RBACDefault } from "../model/rbac";
import { authorizeAsAdmin } from "./commonApi";
import { cloneGroup, Group } from "../model/group";
import { AuthenticationRule, cloneAuthenticationRule } from "../model/authenticationPolicy";
import { cloneAuthenticatonProfile } from "../model/authenticationProfile";
import { AuthorizationRule } from "../model/authorizationPolicy";
import { cloneAuthorizationRule } from "../model/authorizationPolicy";
import { AuthSession } from "../model/authSession";




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
        if (!policy) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthnPolicyNotFound, 'no policy');


        return res.status(200).json(policy);

    }));



routerAuthenticationPolicyAuthenticated.get('/rule/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting authentication policy rule with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const rule = await configService.getAuthenticationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthnRuleNotFound, 'no rule');

        return res.status(200).json(rule);

    }))



routerAuthenticationPolicyAuthenticated.delete('/rule/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`delete authentication rule with id: ${id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;


        const rule = await configService.getAuthenticationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthnRuleNotFound, 'no rule');

        const { before } = await configService.deleteAuthenticationPolicyRule(rule.id);
        //await configService.updateAuthenticationPolicyUpdateTime();
        await auditService.logDeleteAuthenticationPolicyRule(currentSession, currentUser, before);

        return res.status(200).json({});

    }))

routerAuthenticationPolicyAuthenticated.put('/rule/pos/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const input = req.body as { previous: string, current: string, pivot: string };
        logger.info(`changing authentication policy rule pos with id:${id} to previous:${input.previous} current:${input.current}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;


        await inputService.checkIsNumber(input.previous);
        await inputService.checkIsNumber(input.current);
        await inputService.checkIfExists(input.pivot);
        const rule = await configService.getAuthenticationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthnRuleNotFound, 'no rule');

        const pivot = await configService.getAuthenticationPolicyRule(input.pivot);
        if (!pivot) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthnRuleNotFound, 'no rule');


        const previousNumber = Number(input.previous);
        const currentNumber = Number(input.current);
        if (previousNumber < 0 || currentNumber < 0 || previousNumber == currentNumber)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "bad argument");

        const { item, iBefore, iAfter } = await configService.updateAuthenticationRulePos(rule.id, previousNumber, input.pivot, currentNumber);

        await auditService.logUpdateAuthenticationRulePos(currentSession, currentUser, item, iBefore, iAfter);


        return res.status(200).json(rule);

    }))



routerAuthenticationPolicyAuthenticated.put('/rule',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as AuthenticationRule;
        logger.info(`changing authentication policy rule with id:${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkNotEmpty(input.id);
        const rule = await configService.getAuthenticationPolicyRule(input.id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthzRuleNotFound, 'no rule');

        await inputService.checkNotEmpty(input.name);
        await inputService.checkNotEmpty(input.action);
        await inputService.checkNotEmpty(input.networkId);
        await inputService.checkIfExists(input.profile);

        const safe = cloneAuthenticationRule(input);
        //copy original one
        const { before, after } = await configService.saveAuthenticationPolicyRule(safe);
        //await configService.updateAuthenticationPolicyUpdateTime();
        await auditService.logSaveAuthenticationPolicyRule(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerAuthenticationPolicyAuthenticated.post('/rule',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as AuthenticationRule;
        logger.info(`save authentication policy rule with name ${input.name}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkIfNotExits(input.id);


        await inputService.checkNotEmpty(input.name);
        await inputService.checkNotEmpty(input.action);
        await inputService.checkNotEmpty(input.networkId);
        await inputService.checkIfExists(input.profile);
        input.id = Util.randomNumberString(16);
        const safe = cloneAuthenticationRule(input);
        //copy original one
        const { before, after } = await configService.saveAuthenticationPolicyRule(safe);
        //await configService.updateAuthenticationPolicyUpdateTime();
        await auditService.logSaveAuthenticationPolicyRule(currentSession, currentUser, before, after);

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
        if (!policy) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthzPolicyNotFound, 'no policy');


        return res.status(200).json(policy);

    }));



routerAuthorizationPolicyAuthenticated.get('/rule/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");

        logger.info(`getting authorization policy rule with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;

        const rule = await configService.getAuthorizationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthzRuleNotFound, 'no rule');

        return res.status(200).json(rule);

    }))



routerAuthorizationPolicyAuthenticated.delete('/rule/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        logger.info(`delete authorization rule with id: ${id}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const auditService = appService.auditService;

        const rule = await configService.getAuthorizationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthnRuleNotFound, 'no rule');

        const { before } = await configService.deleteAuthorizationPolicyRule(rule.id);
        //await configService.updateAuthorizationPolicyUpdateTime();
        await auditService.logDeleteAuthorizationPolicyRule(currentSession, currentUser, before);

        return res.status(200).json({});

    }))


routerAuthorizationPolicyAuthenticated.put('/rule/pos/:id',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const { id } = req.params;
        if (!id) throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "id is absent");
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const input = req.body as { previous: string, current: string, pivot: string };
        logger.info(`changing authorization policy rule pos with id:${id} to previous:${input.previous} current:${input.current}`);
        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;


        await inputService.checkIsNumber(input.previous);
        await inputService.checkIsNumber(input.current);
        await inputService.checkIfExists(input.pivot);
        const rule = await configService.getAuthorizationPolicyRule(id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthnRuleNotFound, 'no rule');

        const pivot = await configService.getAuthorizationPolicyRule(input.pivot);
        if (!pivot) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthnRuleNotFound, 'no rule');


        const previousNumber = Number(input.previous);
        const currentNumber = Number(input.current);
        if (previousNumber < 0 || currentNumber < 0 || previousNumber == currentNumber)
            throw new RestfullException(400, ErrorCodes.ErrBadArgument, ErrorCodes.ErrBadArgument, "bad argument");

        const { item, iBefore, iAfter } = await configService.updateAuthorizationRulePos(rule.id, previousNumber, input.pivot, currentNumber);
        //await configService.updateAuthenticationPolicyUpdateTime();
        await auditService.logUpdateAuthenticationRulePos(currentSession, currentUser, item, iBefore, iAfter);

        return res.status(200).json(rule);

    }))




routerAuthorizationPolicyAuthenticated.put('/rule',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as AuthorizationRule;
        logger.info(`changing authorization policy rule with id:${input.id}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkNotEmpty(input.id);
        const rule = await configService.getAuthorizationPolicyRule(input.id);
        if (!rule) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrAuthzRuleNotFound, 'no rule');

        await inputService.checkNotEmpty(input.name);
        await inputService.checkNotEmpty(input.serviceId);
        await inputService.checkNotEmpty(input.networkId);
        await inputService.checkIfExists(input.profile);

        const safe = cloneAuthorizationRule(input);
        //copy original one
        const { before, after } = await configService.saveAuthorizationPolicyRule(safe);
        //await configService.updateAuthorizationPolicyUpdateTime();
        await auditService.logSaveAuthorizationPolicyRule(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))

routerAuthorizationPolicyAuthenticated.post('/rule',
    asyncHandler(passportInit),
    asyncHandlerWithArgs(passportAuthenticate, ['jwt', 'headerapikey']),
    asyncHandler(authorizeAsAdmin),
    asyncHandler(async (req: any, res: any, next: any) => {
        const input = req.body as AuthorizationRule;
        logger.info(`save authorization policy rule with name ${input.name}`);
        const currentUser = req.currentUser as User;
        const currentSession = req.currentSession as AuthSession;

        const appService = req.appService as AppService;
        const configService = appService.configService;
        const inputService = appService.inputService;
        const auditService = appService.auditService;

        await inputService.checkIfNotExits(input.id);


        await inputService.checkNotEmpty(input.name);
        await inputService.checkNotEmpty(input.serviceId);
        await inputService.checkNotEmpty(input.networkId);
        await inputService.checkIfExists(input.profile);
        input.id = Util.randomNumberString(16);
        const safe = cloneAuthorizationRule(input);
        //copy original one
        const { before, after } = await configService.saveAuthorizationPolicyRule(safe);
        //await configService.updateAuthorizationPolicyUpdateTime();
        await auditService.saveAuthorizationPolicyRule(currentSession, currentUser, before, after);

        return res.status(200).json(safe);

    }))






