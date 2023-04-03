import { ConfigService } from "./configService";
import * as pvtsutils from "pvtsutils";
import * as pkijs from 'pkijs';
import * as asn1js from "asn1js";
import peculiarCrypto from "@peculiar/webcrypto"

import * as ipaddr from 'ip-address';
import { isIPv4 } from "net";



export class PKIService {
    /**
     *
     */

    constructor(protected configService: ConfigService) {

    }


}