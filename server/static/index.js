const toBase64 = function (buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
};

const fromBase64 = function (str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
};

const serverCert = function () {
    const servercertlist = document.getElementById('servercertlist');
    fetch('/cert/')
        .then(resp => resp.json())
        .then(names => {
            servercertlist.innerText = '';
            names.sort();
            names.forEach(name => {
                const p = document.createElement('p');
                const span = document.createElement('span');
                span.innerText = name;
                const button = document.createElement('button');
                button.innerText = 'download';
                button.addEventListener('click', function () {
                    fetch(`/cert/${name}`)
                        .then(r => r.arrayBuffer())
                        .then(cert => {
                            const file = new Blob([cert]);
                            const link = document.createElement('a');
                            link.href = URL.createObjectURL(file);
                            link.download = `${name}.cert`;
                            link.click();
                        })
                });
                p.appendChild(span);
                p.appendChild(button);
                servercertlist.appendChild(p);
            });
        });
};

const serverCSR = function () {
    const servercsrlist = document.getElementById('servercsrlist');
    fetch('/csr/')
        .then(resp => resp.json())
        .then(names => {
            servercsrlist.innerText = '';
            names.sort();
            names.forEach(name => {
                const p = document.createElement('p');
                const span = document.createElement('span');
                span.innerText = name;
                const button = document.createElement('button');
                button.innerText = 'sign';
                button.addEventListener('click', function () {
                    let ca = localStorage.getItem('ca');
                    if (ca == null) {
                        alert('please load ca');
                        return;
                    }
                    ca = JSON.parse(ca);
                    fetch(`/csr/${name}`)
                        .then(r => r.arrayBuffer())
                        .then(csr => {
                            csr = toBase64(csr);
                            const cert = sign(ca.cert, ca.key, csr);
                            return fetch(`/cert/${name}`, {
                                method: 'POST',
                                body: fromBase64(cert),
                            })
                        })
                        .then(serverCSR)
                        .then(serverCert);
                });
                p.appendChild(span);
                p.appendChild(button);
                servercsrlist.appendChild(p);
            })
        })
};

function localCSR() {
    const csrcreatebutton = document.getElementById('csrcreatebutton');
    const csrnameinput = document.getElementById('csrnameinput');
    const csrname = document.getElementById('csrname');
    const csrpostbutton = document.getElementById('csrpostbutton');
    const refreshCSR = function () {
        let csr = localStorage.getItem("csr");
        if (csr != null) {
            csr = JSON.parse(csr);
            csrname.innerText = csr.name;
            csrpostbutton.disabled = false;
        } else {
            csrname.innerText = '';
            csrpostbutton.disabled = true;
        }
    };
    csrpostbutton.addEventListener('click', function () {
        let csr = JSON.parse(localStorage.getItem("csr"));
        fetch(`/csr/${csr.name}`, {
            method: 'POST',
            body: fromBase64(csr.csr),
        })
            .then(resp => {
                if (resp.status === 200) {
                    localStorage.removeItem('csr');
                    refreshCSR();
                    serverCSR();
                } else {
                    alert(resp.statusText)
                }
            }).catch(e => alert(e));
    });
    csrcreatebutton.addEventListener('click', function () {
        const name = csrnameinput.value;
        if (name.length > 0) {
            const csr = makeCSR(name);
            localStorage.setItem('csr', JSON.stringify(csr));
            const keys = JSON.parse(localStorage.getItem('keys') || '{}');
            keys[name] = csr.key;
            localStorage.setItem('keys', JSON.stringify(keys));
            refreshCSR();
            localKey();
        }
    });
    refreshCSR();
}

const localKey = function () {
    const localkeylist = document.getElementById('localkeylist');
    const keys = JSON.parse(localStorage.getItem('keys') || '{}');
    localkeylist.innerText = '';
    Object.keys(keys).forEach(name => {
        const p = document.createElement('p');
        const span = document.createElement('span');
        span.innerText = name;
        const button = document.createElement('button');
        button.innerText = 'download';
        button.addEventListener('click', function () {
            console.log(keys);
            const file = new Blob([fromBase64(keys[name])]);
            const link = document.createElement('a');
            link.href = URL.createObjectURL(file);
            link.download = `${name}.key`;
            link.click();
        });
        p.appendChild(span);
        p.appendChild(button);
        localkeylist.appendChild(p);
    })
};

const localCA = function () {
    const loadedca = document.getElementById('loadedca');
    const cafiles = document.getElementById("cafiles");
    const caloadbutton = document.getElementById("caloadbutton");
    const refreshCA = function () {
        let ca = localStorage.getItem('ca');
        if (ca != null) {
            ca = JSON.parse(ca);
            loadedca.innerText = ca.name;
        }
    };
    refreshCA();
    caloadbutton.addEventListener('click', function () {
        const files = cafiles.files;
        if (files.length !== 2) {
            console.log('need two files');
            return;
        }
        Promise.all([files[0].arrayBuffer(), files[1].arrayBuffer()])
            .then(([f1, f2]) => {
                const ca = getCAInfo(toBase64(f1), toBase64(f2));
                localStorage.setItem('ca', JSON.stringify(ca));
                refreshCA();
            });
    })
};

const go = new Go();
WebAssembly.instantiateStreaming(fetch("cert.wasm"), go.importObject)
    .then(result => {
        setTimeout(function () {
            localCA();
            localCSR();
            localKey();
            serverCSR();
            serverCert();
        }, 100);
        return go.run(result.instance);
    });

