import { SecurityProfile } from "./securityProfile";

export interface Group {
    id: string;
    name: string;
    securityProfile?: SecurityProfile;
}