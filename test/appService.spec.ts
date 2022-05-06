
import chai from 'chai';
import chaiHttp from 'chai-http';
import fs, { read } from 'fs';
import { ConfigService } from '../src/service/configService';
import { app } from '../src/index';
import { User } from '../src/model/user';
import { AppService } from '../src/service/appService';


chai.use(chaiHttp);
const expect = chai.expect;

// this class is container for other classes
describe('appService', async () => {

    beforeEach((done) => {

        done();
    })


});