
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { config } from 'process';
import { AuthSettings } from '../src/model/authSettings';
import * as twofactor from 'node-2fa';
import { Gateway } from '../src/model/network';
import { Network } from '../src/model/network';
import passport from 'passport';
import passportCustom from 'passport-custom';
import { passportAuthenticate, passportConf } from '../src/api/auth/passportInit';
import { asyncHandlerWithArgs } from '../src/common';

chai.use(chaiHttp);
const expect = chai.expect;




describe('passportInit', async () => {

    let tmp: string[] = [];
    beforeEach(async () => {
        tmp = passportConf.activeStrategies;
        passportConf.activeStrategies = ['test', 'test2'];

    })
    afterEach(async () => {
        passportConf.activeStrategies = tmp as any;

    })


    it('passportAuthenticate empty strategy', (done) => {


        let req = {};
        let res = {};
        let next = (val: any) => {
            expect(val).exist;
            expect(val instanceof Error).to.be.true;
            expect(val.message).to.be.equal('no method');

        };

        passportAuthenticate(req, res, next, []);


        let next2 = (val: any) => {
            expect(val).exist;
            expect(val instanceof Error).to.be.true;
            expect(val.message).to.be.equal('no method');


        };
        asyncHandlerWithArgs(passportAuthenticate, [])(req, res, next2);
        let next3 = (val: any) => {
            expect(val).exist;
            expect(val instanceof Error).to.be.true;
            expect(val.message).to.be.equal('no method');


        };

        asyncHandlerWithArgs(passportAuthenticate, '')(req, res, next3);

        let next4 = (val: any) => {
            expect(val).exist;
            expect(val instanceof Error).to.be.true;
            expect(val.message).to.be.equal('no method');
            done();

        };
        asyncHandlerWithArgs(passportAuthenticate)(req, res, next4);

    }).timeout(50000);

    it('passportAuthenticate 1 strategy with success', (done) => {


        passport.use('test', new passportCustom.Strategy(
            async (req: any, done: any) => {
                req.user = { name: 'quik' };
                return done(null, req.user);

            }
        ));

        let req = {};
        let res = {};
        let next = (val: any) => {
            expect(val).to.be.undefined;
            done();
        };
        asyncHandlerWithArgs(passportAuthenticate, ['test'])(req, res, next);

    }).timeout(50000);


    it('passportAuthenticate 1 known strategy  and 1 unknown', (done) => {


        passport.use('test', new passportCustom.Strategy(
            async (req: any, done: any) => {
                req.user = { name: 'quik' };
                return done(null, req.user);

            }
        ));

        let req = {};
        let res = {};
        let next = (val: any) => {
            expect(val.message).to.exist;
            done();
        };
        asyncHandlerWithArgs(passportAuthenticate, ['test2', 'test'])(req, res, next);

    }).timeout(50000);

    it('passportAuthenticate 1 known strategy  and 1 unknown again', (done) => {

        //if order changes than no error 
        passport.use('test', new passportCustom.Strategy(
            async (req: any, done: any) => {
                req.user = { name: 'quik' };
                return done(null, req.user);

            }
        ));

        let req = {};
        let res = {};
        let next = (val: any) => {
            expect(val).to.be.undefined
            done();
        };
        asyncHandlerWithArgs(passportAuthenticate, ['test', 'test2'])(req, res, next);

    }).timeout(50000);


    it('passportAuthenticate 2 known strategy and authenticates', (done) => {

        //if order changes than no error 
        passport.use('test', new passportCustom.Strategy(
            async (req: any, done: any) => {

                return done(null, null, { error: 'adfadfa' });

            }
        ));
        passport.use('test2', new passportCustom.Strategy(
            async (req: any, done: any) => {
                req.user = { username: 'de' }
                return done(null, { error: 'adfadfa' });
            }
        ));

        let req = {} as any;;
        let res = {};
        let next = (val: any) => {
            expect(val).to.be.undefined
            expect(req.user).exist;
            done();
        };
        asyncHandlerWithArgs(passportAuthenticate, ['test', 'test2'])(req, res, next);

    }).timeout(50000);
})
