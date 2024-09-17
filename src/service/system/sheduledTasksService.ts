import { ConfigService } from "../configService";
import { ClearTmpFolderTask, ImportExternalConfigTask } from "./scheduledTasks";

export class ScheduledTasksService {
    deleteTmpUpLoadFolder: ClearTmpFolderTask;
    deleteTmpPkiFolder: ClearTmpFolderTask;
    externalConfigTask: ImportExternalConfigTask;

    /**
     *
     */
    constructor(private configService: ConfigService) {
        this.deleteTmpUpLoadFolder = new ClearTmpFolderTask('/tmp/uploads', 6 * 60 * 60 * 1000);//6hours check
        this.deleteTmpPkiFolder = new ClearTmpFolderTask('/tmp/pki', 5 * 60 * 1000, 5 * 60 * 1000);//5 minutes
        this.externalConfigTask = new ImportExternalConfigTask(1 * 60 * 1000, configService, '/etc/ferrumgate/env');

    }

    async start() {
        await this.deleteTmpUpLoadFolder.start();
        await this.deleteTmpPkiFolder.start();
    }
    async stop() {
        await this.deleteTmpUpLoadFolder.stop();
        await this.deleteTmpPkiFolder.stop();
    }
}