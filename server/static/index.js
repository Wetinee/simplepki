const toBase64 = function (buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
};

const fromBase64 = function (str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
};

const serverCert = function (cacerfile) {
    const servercertlist = document.getElementById('servercertlist');
    const keys = JSON.parse(localStorage.getItem('keys') || '{}');
    fetch('/cer/')
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
                    fetch(`/cer/${name}`)
                        .then(r => r.arrayBuffer())
                        .then(cert => {
                            const file = new Blob([cert]);
                            const link = document.createElement('a');
                            link.href = URL.createObjectURL(file);
                            link.download = `${name}.cer`;
                            link.click();
                        })
                });
                p.appendChild(span);
                p.appendChild(button);
                if (Object.keys(keys).includes(name)) {
                    const pwLabel = document.createElement('span');
                    pwLabel.innerText = 'password';
                    p.appendChild(pwLabel);
                    const pw = document.createElement('input');
                    p.appendChild(pw);
                    const button2 = document.createElement('button');
                    button2.innerText = 'download pfx';
                    button2.addEventListener('click', function () {
                        fetch(`/cer/${name}`)
                            .then(r => r.arrayBuffer())
                            .then(cer => {
                                const pfx = marshalPFX(toBase64(cer), keys[name], toBase64(cacerfile), pw.value);
                                const file = new Blob([fromBase64(pfx)]);
                                const link = document.createElement('a');
                                link.href = URL.createObjectURL(file);
                                link.download = `${name}.pfx`;
                                link.click();
                            });
                    });
                    p.appendChild(button2);
                }
                servercertlist.appendChild(p);
            });
        });
};

const serverCSR = function (cacerfile) {
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
                            return fetch(`/cer/${name}`, {
                                method: 'POST',
                                body: fromBase64(cert),
                            })
                        })
                        .then(() => serverCSR(cacerfile))
                        .then(() => serverCert(cacerfile));
                });
                p.appendChild(span);
                p.appendChild(button);
                servercsrlist.appendChild(p);
            })
        })
};

function localCSR(cacerfile) {
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
                    serverCSR(cacerfile);
                } else {
                    return resp.text().then(body => Promise.reject(body));
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
            localKey(cacerfile);
        }
    });
    refreshCSR();
}

const localKey = function (cacerfile) {
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

const localCA = function (cacerfile) {
    const loadedca = document.getElementById('loadedca');
    const cakeyfile = document.getElementById('cakeyfile');
    const refreshCA = function () {
        let ca = localStorage.getItem('ca');
        if (ca != null) {
            ca = JSON.parse(ca);
            loadedca.innerText = ca.name;
        }
    };
    refreshCA();
    cakeyfile.addEventListener('change', function () {
        const keyfile = cakeyfile.files[0];
        if (keyfile == null) {
            console.log('need key file');
            return;
        }
        keyfile.arrayBuffer()
            .then(keyfile => {
                const ca = getCAInfo(toBase64(cacerfile), toBase64(keyfile));
                if (ca != null) {
                    localStorage.setItem('ca', JSON.stringify(ca));
                }
                refreshCA();
            });
    })
};

const go = new Go();
WebAssembly.instantiateStreaming(fetch("cert.wasm"), go.importObject)
    .then(result => {
        fetch('/ca.cer')
            .then(resp => resp.arrayBuffer())
            .then(cacerfile => {
                localCA(cacerfile);
                localCSR(cacerfile);
                localKey(cacerfile);
                serverCSR(cacerfile);
                serverCert(cacerfile);
                const refresh = document.getElementById('refreshserver');
                refresh.addEventListener('click', function () {
                    serverCSR(cacerfile);
                    serverCert(cacerfile);
                });
            });
        return go.run(result.instance);
    });

