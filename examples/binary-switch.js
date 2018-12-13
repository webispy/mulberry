const DBus = require('dbus');
const fs = require('fs');

const service = DBus.registerService('system');
const bus = service.bus;
const lightobj = service.createObject('/light/1');

const mylight = {
    value: false
};

/* Light resource object */
lightobj.createInterface('io.mulberry.Resource')
    .addMethod('Get', {
            out: DBus.Define(Object)
        },
        function(callback) {
            console.log('Get', mylight.value);
            callback(null, mylight);
        }
    )
    .addMethod('Post', { in: [DBus.Define(Object)]
        },
        function(asv, callback) {
            mylight.value = asv.value;
            console.log('Post', asv.value);
            callback(null);
        }
    )
    .addMethod('Put', { in: [DBus.Define(String)]
        },
        function(asv, callback) {
            console.log('Put', asv.value);
            callback(null);
        }
    )
    .addMethod('Del', { in: [DBus.Define(Object)]
        },
        function(asv, callback) {
            console.log('Del', asv.value);
            callback(null);
        }
    )
    .update();

function stepAddDevice() {
    return new Promise(function(resolve, reject) {
        bus.getInterface('io.mulberry',
            '/',
            'io.mulberry.Manager',
            function(err, iface) {
                iface.AddDevice(
                    "test",
                    "server",
                    "oic.d.light", {},
                    function(err, result) {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(result);
                        }
                    });
            })
    });
}

function stepAddResource(device_path) {
    return new Promise(function(resolve, reject) {
        bus.getInterface('io.mulberry',
            device_path,
            'io.mulberry.Device',
            function(err, iface) {
                iface.AddResource(
                    "lightbulb",
                    lightobj.path,
                    "/light",
                    "oic.r.switch.binary",
                    "oic.if.a", {},
                    function(err, result) {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(result);
                        }
                    });

            });
    });
}

function stepSetIntrospection(device_path) {
    return new Promise(function(resolve, reject) {
        bus.getInterface('io.mulberry',
            device_path,
            'io.mulberry.Device',
            function(err, iface) {
                const intro = fs.readFileSync('introspection.json', 'utf8');
                iface.SetIntrospection(
                    intro, {},
                    function(err, result) {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(result);
                        }
                    });
            })
    });
}

function stepStartService() {
    return new Promise(function(resolve, reject) {
        bus.getInterface('io.mulberry',
            '/',
            'io.mulberry.Manager',
            function(err, iface) {
                iface.StartService({}, function(err, result) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(result);
                    }
                });
            })
    });
}

let device_dbus_path = null;

stepAddDevice().then(function(result) {
    device_dbus_path = result;
    console.log('device created:', device_dbus_path);
    return stepAddResource(device_dbus_path);
}).then(function(result) {
    console.log('resource registered:', result);
    return stepSetIntrospection(device_dbus_path)
}).then(function(result) {
    console.log('OCF introspection setup success');
    return stepStartService()
}).then(function(result) {
    console.log('service started');
}).catch(function(error) {
    console.log('Failed:', error)
});
