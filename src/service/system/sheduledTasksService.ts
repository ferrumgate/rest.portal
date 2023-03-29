import { ClearTmpFolderTask } from "./scheduledTasks";

export class ScheduledTasksService {
    deleteTmpUpLoadFolder: ClearTmpFolderTask;

    /**
     *
     */
    constructor() {
        this.deleteTmpUpLoadFolder = new ClearTmpFolderTask('/tmp/uploads', 6 * 60 * 60 * 1000);//6hours check

    }

    async start() {
        await this.deleteTmpUpLoadFolder.start();
    }
    async stop() {
        await this.deleteTmpUpLoadFolder.stop();
    }
}