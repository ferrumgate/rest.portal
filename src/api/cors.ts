//cors sample
var allowlist = ['.google.com', '.ferrumgate.com']
export const corsOptionsDelegate = function (req: any, callback: any) {
    var corsOptions;
    const origin = req.header('Origin') as string;
    if (origin && allowlist.find(x => origin.endsWith(x))) {
        corsOptions = { origin: origin, } // reflect (enable) the requested origin in the CORS response
    } else {
        corsOptions = { origin: false } // disable CORS for this request
    }
    callback(null, corsOptions) // callback expects two parameters: error and options
}