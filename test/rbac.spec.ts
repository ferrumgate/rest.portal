
import chai from 'chai';
import chaiHttp from 'chai-http';
import { RBAC, RBACDefault } from '../src/model/rbac';



chai.use(chaiHttp);
const expect = chai.expect;




describe('rbac ', async () => {

    beforeEach(async () => {

    })
    it('default system settings must exit', async () => {

        expect(RBACDefault.systemRightIds).to.have.members(['Admin', 'Reporter', 'User']);
        expect(RBACDefault.systemRoleIds).to.have.members(['Admin', 'Reporter', 'User']);

        expect(RBACDefault.roleAdmin).exist;
        expect(RBACDefault.roleReporter).exist;
        expect(RBACDefault.roleUser).exist;

        expect(RBACDefault.rightAdmin).exist;
        expect(RBACDefault.rightReporter).exist;
        expect(RBACDefault.rightUser).exist;


    }).timeout(5000);

    it('convert2RightList', async () => {
        const rbac: RBAC = {
            roles: [
                RBACDefault.roleAdmin, RBACDefault.roleReporter, RBACDefault.roleUser
            ],
            rights: [
                RBACDefault.rightAdmin, RBACDefault.rightReporter, RBACDefault.rightUser
            ]
        }

        const calculatedRights = RBACDefault.convert2RightList(rbac, ['Admin']);
        expect(calculatedRights).exist;
        expect(calculatedRights.length).to.equal(1);


        const calculatedRights2 = RBACDefault.convert2RightList(rbac, ['Admin', 'Reporter']);
        expect(calculatedRights2.length).to.equal(2);
    })


    it('convert2RightList with new Roles', async () => {
        const rbac: RBAC = {
            roles: [
                RBACDefault.roleAdmin, RBACDefault.roleReporter, RBACDefault.roleUser,
                { id: 'someroleid', name: 'NEW_ROLE', rightIds: ['someid', 'someid2'] }
            ],
            rights: [
                RBACDefault.rightAdmin, RBACDefault.rightReporter, RBACDefault.rightUser,
                { id: 'someid', name: 'DELETE_USER' }, { id: 'someid2', 'name': 'DELETE_ADMIN' }
            ]
        }

        const calculatedRights = RBACDefault.convert2RightList(rbac, ['User', 'someroleid']);
        expect(calculatedRights).exist;
        expect(calculatedRights.length).to.equal(3);
        expect(calculatedRights.map(x => x.id)).to.have.members(['User', 'someid', 'someid2'])



    })
    it('convert2RoleList with new Roles', async () => {
        const rbac: RBAC = {
            roles: [
                RBACDefault.roleAdmin, RBACDefault.roleReporter, RBACDefault.roleUser,
                { id: 'someroleid', name: 'NEW_ROLE', rightIds: ['someid', 'someid2'] }
            ],
            rights: [
                RBACDefault.rightAdmin, RBACDefault.rightReporter, RBACDefault.rightUser,
                { id: 'someid', name: 'DELETE_USER' }, { id: 'someid2', 'name': 'DELETE_ADMIN' }
            ]
        }

        const calculatedRoles = RBACDefault.convert2RoleList(rbac, ['User', 'someroleid']);
        expect(calculatedRoles).exist;
        expect(calculatedRoles.length).to.equal(2);
        expect(calculatedRoles.map(x => x.id)).to.have.members(['User', 'someroleid'])



    })



})


