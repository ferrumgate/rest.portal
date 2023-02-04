import { ConfigService } from "./configService";
import { RedisService } from "./redisService";
// TODO move dhcp codes to here,
/**
 * @summary a dhcp implementation
 */
export class DhcpService {
    /**
     *
     */
    constructor(private configService: ConfigService, private redis: RedisService) {


    }
}