
import log4js from 'log4js';
import { ErrorCodes } from './restfullException';


log4js.configure({
    appenders: { out: { type: 'stdout', layout: { type: 'pattern', pattern: '[%d] [%p] %c - %m' } } },
    categories: { default: { appenders: ['out'], level: 'debug' } }
});

/**
 * @description log4js instance for logging
 * @example logger.error() logger.info() logger.warn() logger.fatal()
 */
export const logger = log4js.getLogger();


/**
 * @description async handler for middleware
 */
export const asyncHandler = (fn: any) => (req: any, res: any, next: any) =>
    Promise
        .resolve(fn(req, res, next))
        .catch(next)

//error middleware

/**
 *  @abstract global error handler middleware
 */
export function globalErrorHandler(err: any, req: any, res: any, nex: any) {

    logger.error(err.stack)
    if (err.status && err.code)
        res.status(err.status).json({ status: err.status, code: err.code, message: err.message });
    else res.status(500).json({ status: 500, code: ErrorCodes.ErrInternalError, message: "internal server error" });

};