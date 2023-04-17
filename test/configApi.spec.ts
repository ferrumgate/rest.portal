
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs from 'fs';
import { AppService } from '../src/service/appService';
import { User } from '../src/model/user';
import { Util } from '../src/util';
import { AuthSettings } from '../src/model/authSettings';
import { EmailSetting } from '../src/model/emailSetting';
import yaml from 'yaml';
import { Email, EmailService } from '../src/service/emailService';
import { ExpressApp } from '../src';


chai.use(chaiHttp);
const expect = chai.expect;




describe('configApi ', async () => {

    const expressApp = new ExpressApp();
    const app = expressApp.app;
    const appService = (expressApp.appService) as AppService;

    const redisService = appService.redisService;
    const configService = appService.configService;
    const sessionService = appService.sessionService;
    const emailService = appService.emailService;

    const user: User = {
        username: 'hamza@ferrumgate.com',
        groupIds: [],
        id: 'someid',
        name: 'hamza',
        source: 'local',
        roleIds: ['Admin'],
        isLocked: false, isVerified: true,
        password: Util.bcryptHash('somepass'),
        insertDate: new Date().toISOString(),
        updateDate: new Date().toISOString()

    }

    before(async () => {
        await expressApp.start();
        if (fs.existsSync('/tmp/config.yaml'))
            fs.rmSync('/tmp/config.yaml')
        await configService.setConfigPath('/tmp/config.yaml');
        const auth: AuthSettings = {
            common: {},
            local: {
                type: 'local',
                baseType: 'local',
                name: 'Local',
                tags: [],
                isForgotPassword: false,
                isRegister: false,
                isEnabled: true,
                insertDate: new Date().toISOString(),
                updateDate: new Date().toISOString()
            },
            saml: { providers: [] },
            ldap: { providers: [] },
            oauth: { providers: [] }

        }
        auth.oauth = {
            providers: [
                {
                    baseType: 'oauth',
                    type: 'google',
                    id: Util.randomNumberString(),
                    name: 'Google',
                    tags: [],
                    clientId: '920409807691-jp82nth4a4ih9gv2cbnot79tfddecmdq.apps.googleusercontent.com',
                    clientSecret: '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',
                    isEnabled: true,
                    insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()
                },
                {
                    baseType: 'oauth',
                    type: 'linkedin',
                    id: Util.randomNumberString(),
                    name: 'Linkedin',
                    tags: [],
                    clientId: '866dr29tuc5uy5',
                    clientSecret: '1E3DHw0FJFUsp1Um',
                    isEnabled: true,
                    insertDate: new Date().toISOString(),
                    updateDate: new Date().toISOString()
                }
            ]
        }

        await configService.setAuthSettingCommon(auth.common);
        await configService.setAuthSettingLocal(auth.local);
        if (auth.ldap?.providers)
            for (const it of auth.ldap.providers) {
                await configService.addAuthSettingLdap(it)
            }
        if (auth.saml?.providers)
            for (const it of auth.saml?.providers) {
                await configService.addAuthSettingSaml(it)
            }
        if (auth.oauth?.providers)
            for (const it of auth.oauth?.providers) {
                await configService.addAuthSettingOAuth(it)
            }

        await configService.setUrl('http://local.ferrumgate.com:8080');
        await configService.setDomain('ferrumgate.zero');
        await configService.setCaptcha(
            {
                client: '6Lcw_scfAAAAABL_DeZVQNd-yNHp0CnNYE55rifH',
                server: '6Lcw_scfAAAAAFKwZuGa9vxuFF7ezh8ZtsQazdS0'
            }
        )
        await configService.init();

    })

    beforeEach(async () => {
        appService.configService.config.users = [];
        await redisService.flushAll();
        configService.config.users = [];


    })

    afterEach(async () => {
        appService.emailService = emailService;
    })
    after(async () => {
        await expressApp.stop();
    })
    it('GET /config/public will return public configs', async () => {

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/public')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.captchaSiteKey).exist;
        expect(response.body.captchaSiteKey).to.equal('6Lcw_scfAAAAABL_DeZVQNd-yNHp0CnNYE55rifH');


    }).timeout(50000);

    it('GET /config/common will return url and domain', async () => {
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/common')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.url).exist;
        expect(response.body.domain).to.equal('ferrumgate.zero');


    }).timeout(50000);

    it('GET /config/common will return 401, only admin users', async () => {
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/common')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);



    }).timeout(50000);


    it('PUT /config/common will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const newValues = {
            domain: 'ferrumgate.com'
        }

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/common')
                .set(`Authorization`, `Bearer ${token}`)
                .send(newValues)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.domain).to.equal('ferrumgate.com');
        expect(response.body.url).to.equal('http://local.ferrumgate.com:8080');



    }).timeout(50000);




    it('GET /config/captcha will return keys', async () => {
        await appService.configService.saveUser(user);

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/captcha')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.server).exist;
        expect(response.body.client).exist;


    }).timeout(50000);

    it('GET /config/captcha will return 401, only admin users', async () => {
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/captcha')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);



    }).timeout(50000);


    it('PUT /config/captcha will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const newValues = {
            server: 'serverkey',
            client: 'clientkey'
        }

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/captcha')
                .set(`Authorization`, `Bearer ${token}`)
                .send(newValues)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.server).to.equal('serverkey');
        expect(response.body.client).to.equal('clientkey');



    }).timeout(50000);

    /// email


    it('GET /config/email will return settings', async () => {
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const EmailSetting: EmailSetting = {
            fromname: 'testferrum', pass: 'apass', type: 'google', user: 'auser'
        }
        await appService.configService.setEmailSetting(EmailSetting);
        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/email')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fromname).to.equal(EmailSetting.fromname);
        expect(response.body.pass).exist;


    }).timeout(50000);

    it('GET /config/email will return 401, only admin users', async () => {
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/email')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);



    }).timeout(50000);


    it('PUT /config/email will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const EmailSetting: EmailSetting = {
            fromname: 'testferrum', pass: 'apass', type: 'google', user: 'auser'
        }
        await appService.configService.setEmailSetting(EmailSetting);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/captcha')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ ...EmailSetting, fromname: 'ferrumgate' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fromname).to.equal('ferrumgate');




    }).timeout(50000);


    it('DELETE /config/email will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const EmailSetting: EmailSetting = {
            fromname: 'testferrum', pass: 'apass', type: 'google', user: 'auser'
        }
        await appService.configService.setEmailSetting(EmailSetting);

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .delete('/config/email')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.fromname).to.equal('');
        expect(response.body.type).to.equal('empty');




    }).timeout(50000);

    it('POST /config/email/check will return 200, with no error', async () => {

        class MockEmail extends EmailService {
            override  async send(email: Email): Promise<void> {

            }
            override  async sendWith(email: Email): Promise<void> {

            }
        }
        appService.emailService = new MockEmail(configService);
        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const EmailSetting: EmailSetting = {
            fromname: 'testferrum', pass: 'nqquxankumksakon', type: 'google', user: 'ferrumgates@gmail.com'
        }


        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/config/email/check')
                .set(`Authorization`, `Bearer ${token}`)
                .send({ settings: EmailSetting, to: 'hamza@hamzakilic.com' })
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.isError).to.equal(false);
        expect(response.body.errorMessage).to.equal('');




    }).timeout(50000);



    it('GET /config/es will return empty object', async () => {
        await appService.configService.saveUser(user);
        await appService.configService.setES({});

        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/es')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.host).not.exist;


    }).timeout(50000);

    it('GET /config/es will return 401, only admin users', async () => {
        const clonedUser = Util.clone(user);
        clonedUser.roleIds = ['User'];
        await appService.configService.saveUser(clonedUser);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/captcha')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(401);



    }).timeout(50000);


    it('PUT /config/es will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const newValues = {
            host: 'serverkey',
        }

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .put('/config/es')
                .set(`Authorization`, `Bearer ${token}`)
                .send(newValues)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.host).to.equal('serverkey');


    }).timeout(50000);


    it('POST /config/es/check will return 200, with new fields', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const newValues = {
            host: 'https://192.168.88.250:9200',
            user: 'elastic',
            pass: '123456'
        }

        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/config/es/check')
                .set(`Authorization`, `Bearer ${token}`)
                .send(newValues)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        expect(response.body.error).to.equal('');


    }).timeout(50000);


    it('GET /config/export will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const newValues = {
            host: 'https://192.168.88.250:9200',
            user: 'elastic',
            pass: '123456'
        }
        const binaryParser = function (res: any, cb: any) {
            res.setEncoding("binary");
            res.data = "";
            res.on("data", function (chunk: any) {
                res.data += chunk;
            });
            res.on("end", function () {
                cb(null, new Buffer(res.data, "binary"));
            });
        };
        await appService.configService.setES(newValues);

        await appService.configService.setIsConfigured(1);
        let response2: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/export/key')
                .set(`Authorization`, `Bearer ${token}`)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response2.status).to.equal(200);
        expect(response2.body.key).exist;



        let response: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .get('/config/export/' + response2.body.key)
                .set(`Authorization`, `Bearer ${token}`)
                .buffer()
                .parse(binaryParser)
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response.status).to.equal(200);
        const buffer = response.body;
        expect(buffer.length).exist;
        const randomFilename = Util.randomNumberString();
        const tmp = `/tmp/${randomFilename}`;
        fs.writeFileSync(tmp, buffer);



        const fileContent = Util.decrypt(response2.body.key, fs.readFileSync(tmp).toString());
        const config = yaml.parse(fileContent);
        expect(config).exist;


    }).timeout(50000);


    it('POST /config/import/:key will return 200', async () => {

        await appService.configService.saveUser(user);
        const session = await sessionService.createSession({ id: 'someid' } as User, false, '1.1.1.1', 'local');
        const token = await appService.oauth2Service.generateAccessToken({ id: 'some', grants: [] }, { id: 'someid', sid: session.id }, 'ferrum')
        const newValues = {
            host: 'https://192.168.88.250:9200',
            user: 'elastic',
            pass: '123456'
        }

        await appService.configService.setES(newValues);
        await appService.configService.setIsConfigured(1);
        const randomfile = `/tmp/${Util.randomNumberString()}.txt`;
        const key = Util.randomNumberString(32);
        const str = Util.encrypt(key, 'hello world');
        fs.writeFileSync(randomfile, str);

        let response2: any = await new Promise((resolve: any, reject: any) => {
            chai.request(app)
                .post('/config/import/' + key)
                .set(`Authorization`, `Bearer ${token}`)
                .set('content-type', 'multipart/form-data')
                .attach('config', fs.readFileSync(randomfile), 'file.png')
                .end((err, res) => {
                    if (err)
                        reject(err);
                    else
                        resolve(res);
                });
        })

        expect(response2.status).to.equal(200);







    }).timeout(50000);




})


