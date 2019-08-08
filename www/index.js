// Copyright 2009-2019 SAP SE or an SAP affiliate company. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

let upload;
let state = {};
let org;
let channel;

$(function () {
    $.get("info", function (data) {
        console.log("info", data);
        org = data.org;
        channel = data.channel;
    });
    document.getElementById("upload").addEventListener("change", readFile);
    $("#propose-update-button").click(function () {
        const description = $("#description").val();
        const idx = upload.indexOf("base64,") + "base64,".length;
        if (idx < 0) {
            setAlert("Please provide an update.")
            return
        }
        const update = upload.substr(idx);
        setAlert("Sending request...")
        $("#proposeUpdateModal").modal('hide')
        $.ajax({
            url: "chaincode/invoke",
            type: "POST",
            dataType: "json",
            contentType: "application/json",
            data: JSON.stringify({
                function: "proposeUpdate",
                args: [guidGenerator(), update, description],
            }),
            success: function (data) {
                console.log("success", data);
                setAlert();
                refreshProposal(data.proposal_id, true);
            },
            error: function (err) {
                setAlert(err);
            },
        });
    });
    refreshProposals();
    websocketConnect();
});

function guidGenerator() {
    return new Date().getTime() + "";
}

function websocketConnect() {
    let url = window.location.href;
    const idx = url.indexOf("//");
    url = url.substr(idx + 2);
    const ws = new WebSocket(`ws://${url}chaincode/events`);
    ws.onopen = function () {
        console.log("Connection open.");
        $("#channelName").text("Channel: "+channel);
    }
    ws.onmessage = function (data) {
        const evt = JSON.parse(data.data);
        console.log("New event", evt);
        const idx = evt.name.indexOf("(");
        if (idx === -1) {
            console.log("event name does not contain id");
            return;
        }
        const id = evt.name.substring(idx + 1, evt.name.length - 1)
        if (evt.name.indexOf("deleteProposalEvent") !== -1) {
            $("#entry-" + id).remove();
        } else {
            refreshProposal(id);
        }
    }
    ws.onclose = function (code, reason) {
        console.log("Connection closed.");
        console.log(code, reason);
        // setTimeout(function () {
        //     console.log("Reconnection to events")
        //     websocketConnect();
        // }, 1000);
    }
    ws.onerror = function (err, x, y) {
        console.log("Websocket error", err, x, y);
    }
}

function generateOrgContent(id) {
    const update = state[id];
    let c = "";
    // create actions
    c += `<div style="position: absolute; top: -15px; right: 15px; z-index: 100;">`
    if (update.signedBy.indexOf(org) === -1) {
        c += `<a class="btn btn-primary text-white" onclick="sign('${id}', '${update.config_update}')">Sign</a> `
    }
    c += `<a class="btn btn-secondary text-white" onclick="downloadProposal('${id}')">Download</a> `
    if (update.creator === org) {
        c += `<a class="btn btn-success text-white" onclick="applyUpdate('${id}')">Apply</a> `
        c += `<a class="btn btn-danger text-white" onclick="deleteProposal('${id}')">Delete</a> `
    }
    c += `</div>` // close actions

    // create info
    c += `<div class="col-sm-12 col-md-6">`;
    if (update.description && update.description.length > 0) {
        c += `${update.description}</br></br>`
    }
    c += `<strong>Creator:</strong> ${update.creator}</br>`

    if (update.added && update.added.length > 0) {
        c += `<strong>New organizations to be added:</strong> ${update.added.join(", ")}</br>`
    }
    if (update.removed && update.removed.length > 0) {
        c += `<strong>Organizations to be removed</strong> ${update.removed.join(", ")}</br>`
    }
    c += `</div>` // close info col

    // create signatures
    c += `<div class="col-sm-12 col-md-6">`
    c += `<h4>Signatures (${update.signedBy.length})</h4>`
    c += `<ul class="list-group">`
    for (const org in update.signatures) {
        c += `<li class="list-group-item d-flex justify-content-between align-items-center">
        ${org}
        <span class="badge badge-primary badge-pill">${update.signatures[org].substr(0, 13)}...</span>
        </li>`
    }
    c += `</ul>`
    c += `</div>`
    return c
}

function renderProposal(id) {
    const content = generateOrgContent(id);
    const e = $("#content-" + id);
    if (!e.length) {
        const update = state[id];
        $("#accordion").append(`<div class="card history-entry" id="entry-${id}">
            <div class="card-header" role="tab" id="heading-${id}">
                <a class="collapsed" data-toggle="collapse" href="#collapse-${id}" aria-expanded="false" style="color: black;">
                    ${update.creator}: ${update.description}
                </a>
            </div>
            <div id="collapse-${id}" class="collapse" role="tabpanel" aria-labelledby="heading-${id}" data-nr="${id}">
                <div class="card-body">
                    <div class="row" id="content-${id}" style="margin-top: 10px; position: relative;">${content}</div>
                </div>
            </div>
        </div > `);
    } else {
        e.html(content);
    }
}

function renderState() {
    $("#accordion").empty();
    for (const id in state) {
        renderProposal(id);
    }
}

function refreshProposal(id, show) {
    $.ajax({
        url: "chaincode/query",
        type: "POST",
        dataType: "json",
        contentType: "application/json",
        data: JSON.stringify({
            function: "getProposal",
            args: [id],
        }),
        success: function (data) {
            setAlert();
            if (!state[id]) {
                state[id] = {};
            }
            state[id].creator = data.creator;
            state[id].description = data.description;
            state[id].signedBy = Object.keys(data.signatures || {});
            state[id].signatures = data.signatures;
            state[id].config_update = data.config_update;
            // decodeUpdate calls renderProposal
            decodeUpdate(id, data.config_update, function () {
                if (show) {
                    $("#collapse-" + id).collapse('show');
                }
            });
        },
        error: function (err) {
            setAlert(err);
        },
    });
}

function refreshProposals() {
    $.ajax({
        url: "chaincode/query",
        type: "POST",
        dataType: "json",
        contentType: "application/json",
        data: JSON.stringify({
            function: "getProposals",
            args: [],
        }),
        success: function (data) {
            setAlert();
            for (const id in data) {
                if (!state[id]) {
                    state[id] = {};
                }
                state[id].creator = data[id].creator;
                state[id].description = data[id].description;
                state[id].signedBy = Object.keys(data[id].signatures || {});
                state[id].signatures = data[id].signatures;
                state[id].config_update = data[id].config_update;
            }
            renderState();
            for (const id in data) {
                decodeUpdate(id, data[id].config_update);
            }
        },
        error: function (err) {
            setAlert(err);
        },
    });
}

function sign(id, update) {
    setAlert("Signing proposal...");
    $.ajax({
        url: "/sign",
        type: "POST",
        dataType: "text",
        contentType: "application/json",
        data: JSON.stringify({ id: id, update: update }),
        success: function (data) {
            setAlert();
            refreshProposal(id, true);
        },
        error: function (err) {
            console.log("sign error", err);
            setAlert(err);
        },
    });
}

function deleteProposal(id, ok) {
    if (!ok && !confirm("Are you sure you want to delete this proposal?")) {
        return
    }
    setAlert("Deleting proposal...");
    $.ajax({
        url: "chaincode/invoke",
        type: "POST",
        dataType: "text",
        contentType: "application/json",
        data: JSON.stringify({
            function: "deleteProposal",
            args: [id],
        }),
        success: function (data) {
            setAlert();
            delete state[id];
            $("#entry-" + id).remove();
        },
        error: function (err) {
            console.log("delete error", err);
            setAlert(err);
        },
    });
}


function decodeUpdate(id, update, callback) {
    $.ajax({
        url: "decode/update",
        type: "POST",
        data: update,
        success: function (data) {
            setAlert();
            if (!data || !data.read_set || !data.read_set.groups || !data.read_set.groups.Application || !data.read_set.groups.Application.groups) {
                console.log("invalid update format", data);
                return
            }
            const oldO = Object.keys(data.read_set.groups.Application.groups);
            const newO = Object.keys(data.write_set.groups.Application.groups);
            state[id].added = _.difference(newO, oldO);
            state[id].removed = _.difference(oldO, newO);
            renderProposal(id);
            if (typeof callback === "function") {
                callback();
            }
        },
        error: function (err) {
            console.log("decode error", err);
            setAlert(err);
        },
    });
}

function readFile() {
    if (this.files && this.files[0]) {
        var FR = new FileReader();
        FR.addEventListener("load", function (e) {
            upload = e.target.result;
        });
        FR.readAsDataURL(this.files[0]);
    }
}

function setAlert(msg) {
    if (!msg) {
        $("#alert").css("display", "none");
        return
    }
    if (msg.status) {
        msg = `${msg.status} (${msg.statusText}): ${msg.responseText || "unknown error"} `;
    }
    $("#alert-text").text(msg.toString());
    $("#alert").css("display", "block");
}

function downloadProposal(id) {
    setAlert("Downloading proposal...")
    $.ajax({
        url: "chaincode/query",
        type: "POST",
        dataType: "json",
        contentType: "application/json",
        data: JSON.stringify({
            function: "getProposal",
            args: [id],
        }),
        success: function (data) {
            setAlert();
            console.log("downloadProposal", id, data);
            download(data, `proposal-${data.creator}-${id}.json`);
        },
        error: function (err) {
            setAlert(err);
        },
    });
}

function applyUpdate(id) {
    const proposal = state[id];
    setAlert("Applying channel update...")
    console.log({
        update: proposal.config_update,
        signatures: proposal.signatures,
    })
    console.log(proposal);
    $.ajax({
        url: "update",
        type: "POST",
        dataType: "text",
        contentType: "application/json",
        data: JSON.stringify({
            update: proposal.config_update,
            signatures: proposal.signatures,
        }),
        success: function (data) {
            setAlert("Success");
            setTimeout(function () {
                deleteProposal(id, true);
            }, 2500)
        },
        error: function (err) {
            setAlert(err);
        },
    });
}

function download(info, filename) {
    const c = JSON.stringify(info);
    const file = new Blob([c], { type: 'text/json' });

    const a = document.createElement('a');
    const url = URL.createObjectURL(file);

    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();

    setTimeout(function () {
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }, 0);
}
