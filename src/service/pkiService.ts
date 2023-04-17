import { ConfigService } from "./configService";
import * as pvtsutils from "pvtsutils";
import * as pkijs from 'pkijs';
import * as asn1js from "asn1js";
import peculiarCrypto from "@peculiar/webcrypto"

import * as ipaddr from 'ip-address';
import { isIPv4 } from "net";
import { SSLCertificate, SSLCertificateEx } from "../model/cert";
import { UtilPKI } from "../utilPKI";
import { logger } from "../common";



export class PKIService {
    /**
     *
     */
    caCerts: pkijs.Certificate[] = [];
    inAuthCerts: pkijs.Certificate[] = [];

    constructor(protected configService: ConfigService) {

    }

    async reload() {
        this.caCerts = []
        this.inAuthCerts = [];
        const ca = await this.configService.getCASSLCertificateSensitive();
        if (ca.publicCrt) {
            try {
                const buffer = UtilPKI.fromPEM(ca.publicCrt);
                const certificate = pkijs.Certificate.fromBER(buffer);
                this.caCerts.push(certificate);
            } catch (ignore) { logger.error(ignore) }
        }
        const inCerts = await this.configService.getInSSLCertificateAllSensitive();
        for (const cert of inCerts) {
            if (cert.category == 'auth' && cert.isEnabled && cert.publicCrt) {
                try {
                    const buffer = UtilPKI.fromPEM(cert.publicCrt);
                    const certificate = pkijs.Certificate.fromBER(buffer);
                    this.inAuthCerts.push(certificate);
                } catch (ignore) { logger.error(ignore) }
            }

        }

    }

    async authVerify(cert: string) {
        return await UtilPKI.verifyCertificate(cert, this.inAuthCerts, this.caCerts, [])
    }


}