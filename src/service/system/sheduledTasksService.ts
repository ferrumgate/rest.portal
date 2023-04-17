import { ClearTmpFolderTask } from "./scheduledTasks";

export class ScheduledTasksService {
    deleteTmpUpLoadFolder: ClearTmpFolderTask;
    deleteTmpPkiFolder: ClearTmpFolderTask;

    /**
     *
     */
    constructor() {
        this.deleteTmpUpLoadFolder = new ClearTmpFolderTask('/tmp/uploads', 6 * 60 * 60 * 1000);//6hours check
        this.deleteTmpPkiFolder = new ClearTmpFolderTask('/tmp/pki', 5 * 60 * 1000, 5 * 60 * 1000);//5 minutes


    }

    async start() {
        await this.deleteTmpUpLoadFolder.start();
    }
    async stop() {
        await this.deleteTmpUpLoadFolder.stop();
    }
}