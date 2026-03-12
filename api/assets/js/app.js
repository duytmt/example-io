document.addEventListener("DOMContentLoaded", function () {
    addParam();

    document.getElementById("method").dispatchEvent(new Event("change"));
    document.getElementById("sendBtn").addEventListener("click", sendRequest);
});


    document.getElementById("method").addEventListener("change", function () {
    const bodyBox = document.getElementById("bodyBox");
    const bodyInput = document.getElementById("body");

    // Hiển thị body khi POST / PUT
    if (this.value === "POST" || this.value === "PUT") {
        bodyBox.style.display = "block";
    } else {
        bodyBox.style.display = "none";
        bodyInput.value = ""; // clear body khi GET / DELETE
    }

    // Highlight DELETE
    this.classList.toggle("method-danger", this.value === "DELETE");
});

function addParam() {
    let paramsBox = document.getElementById("params");

    if (!paramsBox) {
        console.error("Không tìm thấy element #params");
        return;
    }

    let div = document.createElement("div");
    div.className = "param-row";

    div.innerHTML = `
        <input type="text" placeholder="Key" class="key">
        <input type="text" placeholder="Value" class="value">
        <button type="button" class="remove-btn" onclick="this.parentNode.remove()">×</button>
    `;

    paramsBox.appendChild(div);
}

async function sendRequest() {
    let url = document.getElementById("url").value.trim();
    let method = document.getElementById("method").value;

    if (!url) {
        alert("Vui lòng nhập URL");
        return;
    }

    // Chặn gửi DELETE nhầm
    if (method === "DELETE") {
        const confirmDelete = confirm(
            "⚠️ Bạn đang gửi DELETE request.\nHành động này có thể xóa dữ liệu.\n\nBạn có chắc chắn muốn tiếp tục?"
        );

        if (!confirmDelete) {
            return;
        }
    }


    // Lấy Query Params
    let params = {};
    document.querySelectorAll(".param-row").forEach(row => {
        let key = row.querySelector(".key").value.trim();
        let val = row.querySelector(".value").value.trim();
        if (key) params[key] = val;
    });

    // Gắn query vào URL
    let query = new URLSearchParams(params).toString();
    if (query) url += (url.includes('?') ? '&' : '?') + query;

    let payload = {
        url: url,
        method: method,
        headers: {
            // Có thể thêm header tùy chỉnh ở đây nếu UI hỗ trợ
            "Content-Type": "application/json"
        },
        body: null
    };

    // Body cho POST & PUT & DELETE
    if (method === "POST" || method === "PUT" || method === "DELETE") {
        let bodyText = document.getElementById("body").value.trim();

        if (bodyText) {
            try {
                payload.body = JSON.parse(bodyText);
            } catch (err) {
                alert("Body JSON không hợp lệ!");
                return;
            }
        }
    }


    document.getElementById("resultBox").textContent = "Đang gửi request qua Proxy...";

    try {
        // Gọi đến Proxy Backend thay vì trực tiếp
        let res = await fetch('proxy.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        let text = await res.text();
        let status = res.status;

        // Cố parse JSON nếu được để hiển thị đẹp
        try {
            let json = JSON.parse(text);
            text = JSON.stringify(json, null, 2);
        } catch {}

        if (status >= 400) {
            document.getElementById("resultBox").innerHTML = `Error ${status}:\n${text}`;
            document.getElementById("resultBox").style.color = 'red';
        } else {
            document.getElementById("resultBox").textContent = text;
            document.getElementById("resultBox").style.color = 'var(--text-color)';
        }

    } catch (error) {
        document.getElementById("resultBox").textContent = "Lỗi kết nối tới Proxy: " + error;
        document.getElementById("resultBox").style.color = 'red';
    }
}
