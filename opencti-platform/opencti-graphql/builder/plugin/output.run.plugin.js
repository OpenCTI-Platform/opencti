const { fork } = require('child_process');
// const chalk = require('chalk');

const outputRunPlugin = () => ({
    name: 'output-run',
    setup: (build) => {
        const entryPoint = build.initialOptions.entryPoints[0];
        const sourceRootLen = build.initialOptions.sourceRoot ? build.initialOptions.sourceRoot.length + 1 : 0;
        const outputScript = `${build.initialOptions.outdir ?? '.'}/${entryPoint.substring(sourceRootLen).replace('.ts', '.js')}`;

        let stopProcess;
        let stopping = false;

        const reloadProcess = () => {
            const startProcess = () => {
                const nodeProcess = fork(outputScript).on('exit', (code) => {
                    stopProcess = undefined;
                    if (!stopping) {
                        if (code === 0) {
                            console.log('Restarting process');
                        } else {
                            console.log('Process unexpectedly stops, restarting process');
                        }
                        startProcess();
                    }
                });

                stopProcess = () => {
                    nodeProcess.send('shutdown');
                    nodeProcess.disconnect();
                    stopProcess = undefined;
                };
            };

            if (stopProcess) {
                console.log('Stopping current process');
                stopProcess();
            } else {
                console.log('Starting process');
                startProcess();
            }
        };

        ['SIGTERM', 'SIGINT'].forEach((signal) => process.on(signal, () => {
            if (!stopping) {
                stopping = true;
                console.log(`${signal} received, stopping...`);
                stopProcess?.();
            }
        }));

        build.onStart(() => {
            console.log('Build in progress...');
        });

        build.onEnd((result) => {
            const success = result.errors.length === 0;
            if (success) {
                console.log('Build success!');
                reloadProcess();
            } else {
                console.log('Build failed');
            }
        });
    },
});

module.exports = outputRunPlugin;
