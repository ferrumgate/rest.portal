import { Util } from "../util";
import { ConfigService } from "./configService";

export class BusinessHelperService {
    static async updateCloudSetting(configService: ConfigService, cloudId: string, cloudToken: string, cloudUrl: string) {
        await configService.setCloud({
            cloudId: cloudId,
            cloudToken: cloudToken,
            insertDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            cloudUrl: cloudUrl
        });

        //set ip intelligence source
        let ferrumIpIntelligence = (await configService.getIpIntelligenceSources()).find(x => x.type == 'ferrum');
        if (!ferrumIpIntelligence) {
            ferrumIpIntelligence = {
                id: Util.randomNumberString(16),
                insertDate: new Date().toISOString(),
                name: 'Ferrum',
                type: 'ferrum',
                updateDate: new Date().toISOString(),
                url: cloudUrl,
                apiKey: cloudId + cloudToken
            }
        } else {
            ferrumIpIntelligence.url = cloudUrl;
            ferrumIpIntelligence.apiKey = cloudId + cloudToken;
            ferrumIpIntelligence.updateDate = new Date().toISOString();
        }
        await configService.saveIpIntelligenceSource(ferrumIpIntelligence);
    }
}