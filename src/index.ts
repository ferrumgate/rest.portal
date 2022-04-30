import { asyncHandler, globalErrorHandler, logger } from "./common";


const bodyParser = require('body-parser');
const express = require('express');


const port = Number(process.env.PORT) | 8080;


//express app
export const app = express();


//metrics
//app.use(metricsMiddleware);
//middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));



app.use("/test", asyncHandler(async (req: any, res: any, next: any) => {
    res.status(200).json({ result: "ok" });
}));




/**
 *  @abstract global error handler middleware
 */
app.use(globalErrorHandler);


app.start = function () {

    app.listen(port, () => {
        logger.info('service started on ', port);
    })
}

app.start();





