function form_validate(form) {
    let msg = "<ul>";
    let wg_key = form.querySelector("input[name='wireguard_public_key']").value;
    if (wg_key.length !== 44 || wg_key.slice(-1) !== "=") {
        msg += "<li>Invalid Wireguard key</li>";
    }
    try {
        window.atob(wg_key);
    } catch (error) {
        msg += "<li>Invalid Wireguard key</li>";
    }

    let endpoint_enabled = form.querySelector("input[id^='peer-endpoint-enabled']").checked;
    let endpoint = form.querySelector("input[name='endpoint']").value;
    if (endpoint_enabled) {
        if (!endpoint) {
            msg += "<li>Endpoint enabled but not specified</li>";
        } else if (isNaN(endpoint.split(":").at(-1))) {
            msg += "<li>Endpoint doesn't end with a (port) number</li>";
        } else if (endpoint.split(":").length < 2 && endpoint.indexOf(".") === -1) {
            msg += "<li>Endpoint doesn't look like an IP address or FQDN</li>";
        }
    }

    let ipv6ll_enabled = form.querySelector("input[id^='peer-v6ll-enabled']").checked;
    let ipv4_enabled = form.querySelector("input[id^='peer-v4-enabled']").checked;
    let ipv6_enabled = form.querySelector("input[id^='peer-v6-enabled']").checked;

    let ipv6ll = form.querySelector("input[name='ipv6_link_local']").value;
    let ipv4 = form.querySelector("input[name='ipv4']").value;
    let ipv6 = form.querySelector("input[name='ipv6']").value;

    if (!(ipv6ll_enabled || ipv4_enabled || ipv6_enabled)) {
        msg += "<li>At least one IP type has to be enabled and specified</li>";
    }

    if (ipv6ll_enabled) {
        if (!ipv6ll) {
            msg += "<li>IPv6 LinkLocal enabled but not specified</li>";
        } else if (!ipv6ll.startsWith("fe80::")) {
            msg += "<li>IPv6 LinkLocal is not a valid LinkLocal address</li>";
        }
    }
    if (ipv4_enabled) {
        if (!ipv4) {
            msg += "<li>IPv4 enabled but not specified</li>";
        } else if (!(ipv4.startsWith("172.2") || ipv4.startsWith("10.") || ipv4.startsWith("169.254"))) {
            msg += "<li>IPv4 is not a valid dn42/neo/icvpn/LinkLocal address</li>";
        }
    }
    if (ipv6_enabled) {
        if (!ipv6) {
            msg += "<li>IPv6 enabled but not specified</li>";
        } else if (!ipv6.startsWith("fd")) {
            msg += "<li>IPv6 is not a valid fd00::/8 address</li>";
        }
    }

    let bgp_mp = form.querySelector("input[id^='bgp-multi-protocol']").checked;
    let bgp_enh = form.querySelector("input[id^='bgp-extended-next-hop']").checked;
    if (!bgp_mp) {
        if (!(ipv4_enabled && (ipv6_enabled || ipv6ll_enabled))) {
            msg += "<li>Both an IPv4 and IPv6 address must be specified when not having MultiProtocol</li>";
        }
        if (bgp_enh) {
            msg += "<li>Extended next hop is not supported without MultiProtocol</li>";
        }
    }else{
        if (ipv4_enabled){
            msg+= "<li>IPv4 address is not supported with MultiProtocol</li>";
        }
    }
    if (msg !== "<ul>") {
        const errorNode = form.querySelector("div[id^='peer-invalid-note']");
        if (errorNode) {
            errorNode.innerHTML = msg + "</ul>";
        }
        return false;
    } else {
        const errorNode = form.querySelector("div[id^='peer-invalid-note']");
        if (errorNode) {
            errorNode.innerHTML = "";
        }
    }
    let invalidNote = form.querySelector(".mdui-text-color-red");
    if (invalidNote) {
        invalidNote.innerHTML = ""; // Ensure invalidNote is not null before setting innerHTML
    }
    return true;
}

async function refreshTunnelTable() {
    const response = await fetch('/api/tunnels');
    const tunnels = await response.json();
    
    const tbody = document.querySelector('table tbody');
    tbody.innerHTML = '';
    
    tunnels.forEach(tunnel => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${tunnel.wireguard_public_key}</td>
            <td>${tunnel.endpoint || ''}</td>
            <td>${tunnel.ipv6_link_local || ''}</td>
            <td>${tunnel.ipv4 || ''}</td>
            <td>${tunnel.ipv6 || ''}</td>
            <td>${tunnel.multiprotocol_bgp ? 'Yes' : 'No'}</td>
            <td>${tunnel.extended_next_hop ? 'Yes' : 'No'}</td>
            <td>
                <button class="button" onclick="showEditTunnelModal(${tunnel.id});updateConfig${tunnel.id}();">Edit</button>
                <button class="button" onclick="deleteTunnel(${tunnel.id})">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    const table = document.getElementById('tunnelTable');
    const tableHeader = document.getElementById('tunnelTableHeader');

    if (tunnels.length === 0) {
        table.style.display = 'none';
        document.getElementById('tunnel-infomation').style.display = 'none';
    } else {
        table.style.display = 'table';
        document.getElementById('tunnel-infomation').style.display = 'block';
    }

    checkTunnels();
}

async function addTunnel(event) {
    event.preventDefault();
    const form = document.getElementById('editTunnelFormAdd');
    const formData = new FormData(form);
    
    const response = await fetch('/add_tunnel', {
        method: 'POST',
        body: formData
    });
    
    if (response.ok) {
        closeAndResetModal('addTunnelModal', 'editTunnelFormAdd');
        await refreshTunnelTable();
        
    } else {
        const error = await response.text();
        const errorNote = document.getElementById('peer-invalid-noteAdd');
        if (errorNote) {
            errorNote.innerHTML = error;
        }
    }
}

async function deleteTunnel(tunnelId) {
    if (!confirm('Are you sure you want to delete this tunnel?')) {
        return;
    }
    
    const response = await fetch(`/delete_tunnel/${tunnelId}`, {
        method: 'POST'
    });
    
    if (response.ok) {
        await refreshTunnelTable();
    }
}

async function editTunnel(tunnelId, event) {
    event.preventDefault();
    const form = document.getElementById(`editTunnelForm${tunnelId}`);
    const formData = new FormData(form);
    
    const response = await fetch(`/edit_tunnel/${tunnelId}`, {
        method: 'POST',
        body: formData
    });
    
    if (response.ok) {
        closeAndResetModal(`editTunnelModal${tunnelId}`, `editTunnelForm${tunnelId}`);
        await refreshTunnelTable();
    } else {
        const error = await response.text();
        const errorNote = document.getElementById(`peer-invalid-note${tunnelId}`);
        if (errorNote) {
            errorNote.innerHTML = error;
        }
    }
}

function showEditTunnelModal(tunnelId) {
    const modal = document.getElementById('editTunnelModal' + tunnelId);
    modal.style.display = 'block';
    modal.style.zIndex = ++currentMaxZIndex;
    modal.style.top = '100px';
}

function showAddTunnelModal() {
    const modal = document.getElementById('addTunnelModal');
    modal.style.display = 'block';
    modal.style.zIndex = ++currentMaxZIndex;
    modal.style.top = '100px';
}

document.addEventListener('DOMContentLoaded', () => {
    refreshTunnelTable();
});
