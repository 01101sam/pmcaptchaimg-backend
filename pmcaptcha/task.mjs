import {v4} from "uuid";

const taskPool = {};


export class Task {
    constructor() {
        while (1) {
            const assignedId = v4();
            if (taskPool[assignedId]) continue;
            this.id = assignedId;
            break;
        }

        this.status = null;
        this.taskPromise = null;
        this.result = null;
    }

    static async createTask(taskPromise) {
        const task = new Task();
        taskPool[task.id] = task;
        task.status = "processing";
        task.taskPromise = taskPromise;

        taskPromise.then(taskResult => {
            const [result, data] = taskResult;
            // console.debug(taskResult);
            if (result) task.onResolve.bind(task)(data.token);
            else task.onReject.bind(task)(data);
        }).catch(task.onReject.bind(task));
        return task.id;
    }

    async onResolve(result) {
        this.status = "success";
        this.result = result;
    }

    async onReject(error) {
        this.status = "failed";
        this.result = {
            message: error.message,
            stack: error.stack
        }
    }

    static getTask(id) {
        const task = taskPool[id];
        if (!task) return {result: false, code: 404};

        switch (task.status) {
            case "processing":
                return {result: false, code: 204};
            case "success":
            case "failed":
                delete taskPool[id];
                return {
                    result: true,
                    code: 200,

                    taskResult: task.status === "success",
                    data: task.result
                };
        }
    }
}